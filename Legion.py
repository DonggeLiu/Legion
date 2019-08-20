import cProfile as profile
import argparse
import enum
import logging
import os
import pdb
import random
import struct
import subprocess as sp
import time
import datetime
from math import sqrt, log, ceil, inf
from typing import Dict, List

from angr import Project
from angr.sim_state import SimState as State
from angr.storage.file import SimFileStream

# Hyper-parameters
MIN_SAMPLES = 5
MAX_SAMPLES = 100
TIME_COEFF = 0
RHO = 1 / sqrt(2)

MAX_BYTES = 100  # Max bytes per input

# Budget
MAX_PATHS = float('inf')
MAX_ROUNDS = float('inf')
MAX_TIME = 900
FOUND_BUG = False  # type: bool

# Statistics
CUR_ROUND = 0
TIME_START = time.time()
SOLVING_COUNT = 0

# Execution
BINARY = None
DIR_NAME = None
SEEDS = []
BUG_RET = 100  # the return code when finding a bug
SAVE_TESTINPUTS = True
SAVE_TESTCASES = False

INPUTS = []  # type: List
MSGS = []  # type: List
TIMES = []  # type: List

# cache Node
# ROOT = TreeNode()  # type: TreeNode or None

# Logging
LOGGER = logging.getLogger("Legion")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)


# Colour of tree nodes
class Colour(enum.Enum):
    W = 'White'
    R = 'Red'
    G = 'Gold'
    B = 'Black'


# TreeNode:
class TreeNode:
    """
    Colour | TraceJump    | ANGR         | Symex state
    White  | True         | Undetermined | Undetermined
    Red    | True         | True         | False, stored in its simulation child
    Gold   | False        | False        | True, stores its parent's state
    Black  | True         | no sibling   | False
    """

    def __init__(self, addr: int = -1, parent: 'TreeNode' = None,
                 colour: Colour = Colour.W,
                 state: State = None, samples: iter = None):
        # identifier
        self.addr = addr  # type: int
        # Tree relations
        self.parent = parent  # type: TreeNode
        self.children = {}  # type: Dict[int or str, TreeNode]

        # classifiers
        self.colour = colour  # type: Colour
        self.phantom = False  # type: bool

        # concolic execution
        self.state = state  # type: State
        self.samples = samples  # type: iter

        # statistics
        self.sel_try = 0
        self.sel_win = 0
        self.sim_try = 0
        self.sim_win = 0
        # accumulated time spent on APPFuzzing the node
        self.accumulated_time = 0
        # the subtree beneath the node has been fully explored
        self.fully_explored = False

    def score(self) -> float:

        def time_penalisation() -> float:
            """
            :return: Average constraint solving time / Expected sample number
            """
            return average_constraint_solving_time() / expected_sample_num()

        def average_constraint_solving_time() -> float:
            """
            :return: Accumulated con-sol time / accumulated con-sol count
            """
            # For the first time selected, it takes ceil(log(MIN_SAMPLES, 2))
            # to gather MIN_SAMPLES samples
            # For the rest, it takes 1 (estimated value)
            count = ceil(log(MIN_SAMPLES, 2) + self.sel_try - 1)
            return self.accumulated_time / count

        def expected_sample_num() -> float:
            """
            The first time it should return at least MIN_SAMPLES
            the rest doubles the number of all solutions
            :return: MIN_SAMPLES * 2 ^ number of times sampled
            """
            return min(MAX_SAMPLES, MIN_SAMPLES * pow(2, self.sel_try))

        # # Evaluate to minimum value if block node does not have any non-simulation child
        # if self.colour is not Colour.G and (len(self.children.values()) - ('Simulation' in self.children)) == 0:
        #     return -inf

        # Evaluate to minimum value if fully explored
        if self.fully_explored:
            return -inf

        # Evaluate to maximum value if not tried before
        if not self.sel_try:
            return inf

        # Evaluate to maximum value if is root
        if self.is_root():
            return inf

        # Otherwise, follow UCT
        exploit = self.sim_win / self.sel_try
        # sim_try should not be 0 if sel_try is not
        # since the first input must preserve the path
        explore = sqrt(2 * log(self.parent.sel_try) / (
                self.sim_try + 1))  # Hard-coded + 1 on the denominator
        uct_score = exploit + 2 * RHO * explore

        return uct_score - TIME_COEFF * time_penalisation()

    def mark_fully_explored(self):
        """
        Mark a node fully explored
        If the node is simulation node, mark its parent fully explored
        If the node is red, mark its simulation child fully explored
        If all block siblings are fully explored, mark its parent fully explored
        :return:
        """

        if self.colour is Colour.W:
            return

        if not all([c.fully_explored for c in self.children.values() if
                    c.colour is not Colour.G]):
            return

        if not self.sel_try:
            return

        LOGGER.info("Fully explored {}".format(self))
        self.fully_explored = True

        # if self.colour is Colour.G:
        #     self.parent.fully_explored = True

        if self.colour is Colour.R:
            LOGGER.info("Fully explored {}".format(self.children['Simulation']))
            self.children['Simulation'].fully_explored = True

        if self.parent:
            self.parent.mark_fully_explored()

    def best_child(self) -> 'TreeNode':
        """
        Select the child of the highest uct score, break tie uniformly
        :return: a tree node
        """
        # TODO: more elegant method, if time permitted
        max_score, candidates = -inf, []  # type: float, List[TreeNode]
        for child in self.children.values():
            cur_score = child.score()
            if cur_score == max_score:
                candidates.append(child)
                continue
            if cur_score > max_score:
                max_score = cur_score
                candidates = [child]

        # TODO: choose one from candidates uniformly
        return candidates[int(random.uniform(0, len(candidates) - 1))]

    def is_root(self) -> bool:
        """
        All node except the root should have a parent
        :return: if the node is root
        """
        return not self.parent

    def is_leaf(self) -> bool:
        """
        If the node has no other child than simulation node, then it is a leaf
        :return: whether the node is a leaf
        """
        return not self.children or all(
            [child.colour == Colour.G for child in self.children.values()])

    def dye(self, colour: Colour,
            state: State = None, samples: iter = None) -> None:
        """
        Dye a node
        :param colour: the colour to dye to
        :param state: the state to be attached
        :param samples: the samples to be attached
        :return:
        """
        # Don't double dye a node
        debug_assertion(self.colour is Colour.W)
        # All colours should come with a state, except black
        debug_assertion(bool(colour is Colour.B) ^ bool(state))

        self.colour = colour
        if colour is Colour.R:
            # No pre-existing simulation child
            debug_assertion('Simulation' not in self.children)
            self.add_child(key='Simulation',
                           new_child=TreeNode(addr=self.addr, parent=self))
            self.children['Simulation'].dye(
                colour=Colour.G, state=state, samples=samples)
            return

        # Black, Gold, or Purple
        self.state = state
        self.samples = samples

    def is_diverging(self) -> bool:
        """
        If the node has more than one child, except simulation
        :return: True if there are more than one
        """

        return len(self.children) > ('Simulation' in self.children) + 1

    def mutate(self):
        global SOLVING_COUNT
        SOLVING_COUNT += 1
        if self.state and self.state.solver.constraints:
            return self.app_fuzzing()
        return self.random_fuzzing()

    def app_fuzzing(self) -> List[bytes]:
        def byte_len() -> int:
            """
            The number of bytes in the input
            :return: byte length
            """
            return (target.size() + 7) // 8

        target = self.state.posix.stdin.load(0, self.state.posix.stdin.size)

        if not self.samples:
            self.samples = self.state.solver.iterate(e=target)

        results = []
        while len(results) < MAX_SAMPLES:
            try:
                val = next(self.samples)
                if val is None and len(results) >= MIN_SAMPLES:
                    # next val requires constraint solving and enough results
                    break
                if val is None and len(results) < MIN_SAMPLES:
                    # requires constraint solving but not enough results
                    continue
                result = val.to_bytes(byte_len(), 'big')
                results.append(result)
            except StopIteration:
                # NOTE: Insufficient results from APPFuzzing:
                #  Case 1: break in the outside while:
                #       Not more input available from constraint solving
                #       Implies no more undiscovered path in its subtree
                #       should break
                #  Case 2: break in the inside while:
                #       No more solution available from the current sigma
                #       Needs to restart from a new sigma
                #       should continue, and may trigger case 1 next.
                #       even if not, the next constraint solving will take long
                #       as it has to exclude all past solutions
                #  Assume Case 1 for simplicity
                LOGGER.info("Fully explored {}".format(self))
                self.mark_fully_explored()
                break
        return results

    @staticmethod
    def random_fuzzing() -> List[bytes]:
        def random_bytes():
            input_bytes = b''
            for _ in range(MAX_BYTES):
                input_bytes += os.urandom(1)
            return input_bytes

        return [random_bytes() for _ in range(MIN_SAMPLES)]

    def add_child(self, key: str or int, new_child: 'TreeNode') -> None:
        debug_assertion((key == 'Simulation') ^ (key == new_child.addr))
        self.children[key] = new_child

    def match_child(self, addr: int) -> bool:
        """
        Check if the addr matches to an existing child:
            if not, it corresponds to a new path, add the addr as a child
        :param addr: the address to check
        :return: if the addr corresponds to a new path
        """
        # check if the addr corresponds to a new path:
        # Note: There are two cases for addr to be new:
        #   1. addr is not a child of self
        #   2. addr is a phantom child

        child = self.children.get(addr)

        if child == None:
            child = TreeNode(addr=addr, parent=self)
            self.add_child(key=addr, new_child=child)
            return (True, child)
        else:
            is_phantom = child.phantom
            child.phantom = False
            return (is_phantom, child)

    def print_path(self) -> List[str]:
        """
        print all address from root to the current node
        :return: a list of addresses
        """
        path, parent = [], self
        while parent:
            path.append(parent.addr)
            parent = parent.parent
        return path[::-1]

    def pp(self, indent: int = 0,
           mark: 'TreeNode' = None, found: int = 0, forced: bool = False):
        if LOGGER.level > logging.INFO and not forced:
            return
        s = ""
        for _ in range(indent - 1):
            s += "|  "
        if indent > 15 and self.parent and self.parent.colour is Colour.W:
            LOGGER.info("...")
            return
        if indent:
            s += "|-- "
        s += str(self)
        if self == mark:
            s += "\033[1;32m <=< found {}\033[0;m".format(found)
        LOGGER.info(s)
        if self.children:
            indent += 1

        for _, child in sorted(list(self.children.items()),
                               key=lambda k: str(k)):
            child.pp(indent=indent, mark=mark, found=found, forced=forced)

    def repr_node_name(self) -> str:
        return ("Simul: " if self.colour is Colour.G else
                "Block: " if self.parent else "@Root: ") \
               + (hex(self.addr)[-4:] if self.addr else "None")

    def repr_node_data(self) -> str:
        """
        UCT = sim_win / sel_try
            + 2 * RHO * sqrt(2 * log(self.parent.sel_try) / self.sim_try)
        :return:
        """
        return "{uct:.2f} = {simw}/{selt} " \
               "+ 2*{r:.2f}*sqrt(log({pselt})/{simt}) " \
               "- {t:.2f}*{at:.2f}/({selt}+log({MS}, 2)-1)/{MS}*2^{selt})" \
            .format(uct=self.score(), simw=self.sim_win, selt=self.sel_try,
                    r=RHO, pselt=self.parent.sel_try if self.parent else inf,
                    simt=self.sim_try,
                    t=TIME_COEFF, at=self.accumulated_time, MS=MIN_SAMPLES)

    def repr_node_state(self) -> str:
        return "{}".format(self.state) if self.state else "NoState"

    def __repr__(self) -> str:
        return '\033[1;{colour}m{name}: {data}, {state}\033[0m' \
            .format(colour=30 if self.colour is Colour.B else
                    31 if self.colour is Colour.R else
                    33 if self.colour is Colour.G else
                    37 if self.colour is Colour.W else 32,
                    name=self.repr_node_name(),
                    state=self.repr_node_state(),
                    data=self.repr_node_data())


ROOT = TreeNode()


def run() -> None:
    """
    The main function
    :return:
    """
    initialisation()
    ROOT.pp()
    while has_budget():
        mcts()


def initialisation():
    def init_angr():
        return Project(thing=BINARY, ignore_functions=['printf',
                                                       '__trace_jump',
                                                       '__trace_jump_set'])

    def init_root() -> TreeNode:
        """
        NOTE: prepare the root (dye red, add simulation child)
            otherwise the data in simulation stage of SEEDs
            cannot be recorded without building another special case
            recorded in the simulation child of it.
            Cannot dye root with dye_to_the_next_red() as usual, as:
                1. The addr of root will not be known before simulation
                2. The function requires a red node
                    in the previous line of the node to dye,
                    which does not exist for root
        """
        root = TreeNode()
        root.dye(colour=Colour.R,
                 state=project.factory.entry_state(stdin=SimFileStream))
        return root

    def init_seeds():
        """
        Inset \n between every element
        """
        global SEEDS
        tmp = []
        for seed in SEEDS:
            tmp.extend([seed, '\n'])
        SEEDS = tmp

    global ROOT
    project = init_angr()
    ROOT = init_root()
    init_seeds()
    traces = simulation(node=ROOT, input_strs=SEEDS)
    ROOT.addr = traces[0][0]
    are_new = expansion(traces=traces)
    propagation(node=ROOT.children['Simulation'], traces=traces,
                are_new=are_new)
    save_news_to_file(are_new=are_new)


def has_budget() -> bool:
    """
    Control whether to terminate mcts or not
    :return: True if terminate
    """
    return not FOUND_BUG and ROOT.sim_win < MAX_PATHS and ROOT.score() > -inf \
        and CUR_ROUND < MAX_ROUNDS and (time.time() - TIME_START) < MAX_TIME


def mcts():
    """
    The four steps of MCTS
    """
    node = selection()
    if node is ROOT:
        return
    traces = simulation(node=node)
    are_new = expansion(traces=traces)
    debug_assertion(len(traces) == len(are_new))
    propagation(node=node, traces=traces, are_new=are_new)
    ROOT.pp(mark=node, found=sum(are_new))
    save_news_to_file(are_new=are_new)


def selection() -> TreeNode:
    """
    Repeatedly apply tree policy until a simulation node is selected
    # :param node: the node to start selection on
    :return: nodes along the selection path
    """

    def dye_node(target: TreeNode, states: List[State]) -> List[State]:
        """
        Since the target is white, dye it and its siblings
        :param target: the node to dye
        :param states: the states to dye the target and its siblings
        :return: the states left after dying (i.e. because the node is black)
        """
        states = dye_siblings(parent=target.parent, target_states=states)
        # NOTE: if the node is dyed to red,
        #  it means all states left must belong to its siblings
        if target.colour is Colour.R:
            add_children(parent=target.parent, states=states)
            states = []
        return states

    node, states_left = ROOT, []
    while node.colour is not Colour.G:

        # If the nod is already a red leaf, mark it as fully explored
        # Note: Must check this before dying,
        #  otherwise a phantom red node added when dying its sibling will be wrongly marked as fully explored
        if node.is_leaf() and node.colour is Colour.R:
            node.mark_fully_explored()

        # If the node is white, dye it
        if node.colour is Colour.W:
            states_left = dye_node(target=node, states=states_left)

            # IF the node is dyed to black and there is no states left,
            # it implies the previous parent state does not have any diverging
            # descendants found by `compute_to_diverging()`, hence the rest of the
            # tree must be fully explored, and there is no difference in fuzzing
            # any of them
            if node.colour is Colour.B and not states_left:
                LOGGER.info("Fully explored {}".format(node))
                node.fully_explored = True

        # If the node's score is the minimum, return ROOT to restart
        if node.score() == -inf:
            return ROOT

        node = tree_policy(node=node)
        LOGGER.info("Select: {}".format(node))

    debug_assertion(not states_left)
    debug_assertion(node.colour is Colour.G)

    return node


def tree_policy(node: TreeNode) -> TreeNode:
    """
    Select the best child of the node
    :param node: the node to select child from
    :return: the child selected
    """
    return node.best_child()


def dye_siblings(parent: TreeNode, target_states: List[State]) -> List[State]:
    """
    If a child of the parent is found white,
    then all children of the parent must also be white;
    This function dyes them all.
    :param parent: the parent of the white child
    :param target_states: previous left states
    :return: a list of states that
            do not match with any of the existing children of the parent,
            they correspond to the child nodes of the parent who
            have not been found by TraceJump
    """

    # if not ('Simulation' in parent.children) ^ bool(target_states):
    #     pdb.set_trace()

    # Case 1: parent is red, then execute parent's state to find states of sibs
    # Case 2: parent is black, use the states left to dye siblings
    # Either 1 or 2, not both
    debug_assertion((parent.colour is Colour.R) ^ bool(target_states))

    if parent.colour is Colour.R:
        debug_assertion(not target_states)
        parent_state = parent.children['Simulation'].state
        target_states = compute_to_diverge(state=parent_state)

        # NOTE: Empty target states implies
        #  the symbolic execution has reached the end of program
        #  without seeing any divergence after the parent's state
        #  hence the parent is fully explored
        if not target_states:
            parent.fully_explored = True

    for child_node in parent.children.values():
        if child_node.colour is Colour.G:
            continue
        target_states = match_node_states(node=child_node, states=target_states)
        debug_assertion(child_node.colour in [Colour.R, Colour.B])

    return target_states


def compute_to_diverge(state: State):
    """
    Symbolically execute to the immediate next diverging states and return its children (must be more than one)
    :param state: the state which is in the line to execute through
    :return: a list of the immediate child states of the line,
        could be empty if the line is a leaf
    """
    child_states = symex(state=state)

    # Terminate if there is a choice
    while len(child_states) == 1:
        # if len(child_states[0].solver.constraints) > len(state.solver.constraints):
        #     # Note: There is at least one unsatisfiable state ignored by ANGR:
        #     #  Because child_state's constraint is different from its parent,
        #     #  but child state does not have any sibling.
        #     #  We should ignore this when fuzzing input
        #     #  cause it does not give us an alternative state to fuzz with
        #     continue
        child_states = symex(state=child_states[0])

    if not child_states:
        LOGGER.info("Symbolic execution reached the end of the program")

    return child_states


def symex(state: State) -> List[State]:
    """
    One step of symbolic execution from state
    :param state: the state to execute from
    :return: the resulting state(s) of symbolic execution
    """
    LOGGER.debug(state)
    return state.step().successors


def match_node_states(node: TreeNode, states: List[State]) -> List[State]:
    """
    If the node matches one of the states, then dye node to red
        and remove it from the list of states
    Else dye the node to black
    :param node: the node to match with state
    :param states: a list of states to match with the node
    :return: a list of states that does not match with the node
    """
    if not states:
        node.dye(colour=Colour.B)
        # NOTE: Empty target states implies
        #  the symbolic execution has reached the end of program
        #  without seeing any divergence after the parent's state
        #  hence the parent is fully explored
        node.mark_fully_explored()
        return states

    for state in states:
        # try to match each state to the node
        if node.addr == state.addr:
            node.dye(colour=Colour.R, state=state)
            states.remove(state)

    if node.colour is Colour.W:
        node.dye(colour=Colour.B)

    return states


def add_children(parent: TreeNode, states: List[State]) -> None:
    """
    Given all states that do not match with any of the parent's child nodes,
    it implies those nodes have not been discovered by TraceJump.
    The nodes must be there, we might as well add them directly
    :param parent: the parent to which the child nodes will be added
    :param states: the states to which the child nodes correspond
    :return:
    """
    for state in states:
        debug_assertion(state.addr not in parent.children)
        parent.add_child(key=state.addr,
                         new_child=TreeNode(addr=state.addr, parent=parent))
        parent.children[state.addr].dye(colour=Colour.R, state=state)
        parent.children[state.addr].phantom = True
        LOGGER.info("Add Phantom {} to {}".format(state, parent))


def simulation(node: TreeNode, input_strs: List[str] = None) -> List[List[int]]:
    """
    Generate mutants (i.e. inputs that tend to preserve the path to the node)
    Execute the instrumented binary with mutants to collect the execution traces
    :param node: the node to fuzz
    :param input_strs: a predefined list of input_strs to be executed
    :return: the execution traces
    """
    mutants = [bytes("".join(mutant), 'utf-8') for mutant in
               input_strs] if input_strs else node.mutate()
    return [binary_execute(mutant) for mutant in mutants if not FOUND_BUG]


def binary_execute(input_bytes: bytes) -> List[int]:
    """
    Execute the binary with an input in bytes
    :param input_bytes: the input to feed the binary
    :return: the execution trace in a list
    """

    time_stamp = time.time() - TIME_START

    def unpack(output):
        debug_assertion((len(output) % 8 == 0))
        # NOTE: changed addr[0] to addr
        return [addr for i in range(int(len(output) / 8))
                for addr in struct.unpack_from('q', output, i * 8)]

    def execute():
        program = sp.Popen(BINARY, stdin=sp.PIPE, stdout=sp.PIPE,
                           stderr=sp.PIPE, close_fds=True)
        try:
            msg = program.communicate(input_bytes, timeout=30 * 60 * 60)
            ret = program.returncode

            program.kill()
            del program
            return msg, ret
        except sp.TimeoutExpired:
            LOGGER.error("Binary execution time out")
            exit(2)

    global FOUND_BUG, MSGS, INPUTS, TIMES

    report = execute()
    debug_assertion(bool(report))

    report_msg, return_code = report
    output_msg = report_msg[0].decode('utf-8')
    error_msg = report_msg[1]

    if SAVE_TESTCASES or SAVE_TESTINPUTS:
        TIMES.append(time_stamp)
        if SAVE_TESTCASES:
            MSGS.append(output_msg)
        if SAVE_TESTINPUTS:
            INPUTS.append(input_bytes)

    if return_code == BUG_RET:
        FOUND_BUG = True
        print("\n*******************"
              "\n***** EUREKA! *****"
              "\n*******************\n")
    return unpack(error_msg)


def expansion(traces: List[List[int]]) -> List[bool]:
    """
    The expansion step of MCTS.
    Expand the search tree with each of the traces
    :param traces: the traces to be integrated into the tree
    :return: a list of booleans representing whether each trace contribute to a new path
    """
    return [integrate_path(trace=trace) for trace in traces]


def integrate_path(trace: List[int]) -> bool:
    """
    Integrate a trace into the search tree, return True if the trace contributes to a new path
    :param trace: the trace to be integrated into the tree
    :return: a bool representing whether the trace contributes to a new path
    """
    debug_assertion(trace[0] == ROOT.addr)

    node, is_new = ROOT, False
    for addr in trace[1:]:
        new_child, child = node.match_child(addr=addr)
        is_new = is_new or new_child
        node = child
    return is_new


def propagation(node: TreeNode, traces: List[List[int]],
                are_new: List[bool]) -> None:
    """
    The propagration step of MCTS.
    Propagate the results to the selection path and each execution trace
    :param node: the node selected by selection step
    :param traces: the binary execution traces
    :param are_new: whether each of the execution traces is new
    """
    propagate_selection_path(node=node, are_new=are_new)
    propagate_execution_traces(traces=traces, are_new=are_new)


def propagate_selection_path(node: TreeNode, are_new: List[bool]) -> None:
    """
    Back-propagate selection counter to each node in the selection path
    :param node: the node selected in selection step
    :param are_new: whether each of the execution traces is new
    :return:
    """
    while node:
        node.sel_try += len(are_new)
        # node.sim_win += sum(are_new)
        node = node.parent


def propagate_execution_traces(traces: List[List[int]],
                               are_new: List[bool]) -> None:
    """
    Forward propagate the results to all execution traces correspondingly
    :param traces: the binary execution traces
    :param are_new: whether each of the execution traces is new
    """

    def propagate_execution_trace(trace: List[int], is_new: bool) -> None:
        """
        Forward propagate the results to all execution traces correspondingly
        :param trace: the binary execution trace
        :param is_new: whether the execution trace is new
        """
        debug_assertion(trace[0] == ROOT.addr)
        node = ROOT
        record_simulation(node=node, new=is_new)
        for addr in trace[1:]:
            node = node.children[addr]
            record_simulation(node=node, new=is_new)

        # NOTE: mark the last node as fully explored
        #   as fuzzing it will not give any new path
        node.mark_fully_explored()

    def record_simulation(node: TreeNode, new: bool) -> None:
        """
        Record a node has been traversed in simulation
        NOTE: increment the statistics of its simulation child as welll
            otherwise it will always have sim_try = 0
        :param node: the node to record
        :param new: whether the node contributes to the discovery of a new path
        """
        node.sim_win += new
        node.sim_try += 1
        if 'Simulation' in node.children:
            node.children['Simulation'].sim_try += 1

    debug_assertion(len(traces) == len(are_new))
    for i in range(len(traces)):
        propagate_execution_trace(trace=traces[i], is_new=are_new[i])


def save_news_to_file(are_new):
    """
    Save data to file only if it is new
    :param are_new: a list to represent whether each datum
                    contributes to a new path
    """
    global MSGS, INPUTS, TIMES
    # debug_assertion(len(are_new) == len(MSGS) == len(INPUTS) == len(TIMES))
    if not SAVE_TESTCASES and not SAVE_TESTINPUTS:
        return
    for i in range(len(are_new)):
        if are_new[i] and SAVE_TESTCASES:
            save_tests_to_file(TIMES[i], MSGS[i])
        if are_new[i] and SAVE_TESTINPUTS:
            save_input_to_file(TIMES[i], INPUTS[i])
    MSGS, INPUTS, TIMES = [], [], []


def save_tests_to_file(time_stamp, data):
    # if DIR_NAME not in os.listdir('tests'):
    with open('tests/{}/{}_{}.xml'.format(
            DIR_NAME, time_stamp, SOLVING_COUNT), 'wt') as input_file:
        input_file.write(
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
        input_file.write(
            '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" "https://sosy-lab.org/test-format/testcase-1.1.dtd">\n')
        input_file.write('<testcase>\n')
        input_file.write(data)
        input_file.write('</testcase>\n')


def save_input_to_file(time_stamp, input_bytes):
    # if DIR_NAME not in os.listdir('inputs'):
    os.system("mkdir -p inputs/{}".format(DIR_NAME))

    with open('inputs/{}/{}_{}'.format(
            DIR_NAME, time_stamp, SOLVING_COUNT), 'wb') as input_file:
        input_file.write(input_bytes)


def debug_assertion(assertion: bool) -> None:
    if LOGGER.level <= logging.DEBUG and not assertion:
        pdb.set_trace()
        return
    assert assertion


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Legion')
    parser.add_argument('--min-samples', type=int, default=MIN_SAMPLES,
                        help='Minimum number of samples per iteration')
    parser.add_argument('--max-samples', type=int, default=MAX_SAMPLES,
                        help='Maximum number of samples per iteration')
    parser.add_argument('--time-penalty', type=float, default=TIME_COEFF,
                        help='Penalty factor for constraints that take longer to solve')
    # parser.add_argument('--sv-comp', action="store_true",
    #                     help='Link __VERIFIER_*() functions, *.i files implies --source')
    # parser.add_argument('--source', action="store_true",
    #                     help='Input file is C source code (implicit for *.c)')
    # parser.add_argument('--cc',
    #                     help='Specify compiler binary')
    # parser.add_argument('--as',
    #                     help='Specify assembler binary')
    parser.add_argument('--save-inputs', action="store_true",
                        help='Save inputs as binary files')
    parser.add_argument('--save-tests', action="store_true",
                        help='Save inputs as TEST-COMP xml files')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='Increase output verbosity')
    parser.add_argument("file",
                        help='Binary or source file')
    parser.add_argument("seeds", nargs='*',
                        help='Optional input seeds')
    args = parser.parse_args()

    MIN_SAMPLES = args.min_samples
    MAX_SAMPLES = args.max_samples
    TIME_COEFF = args.time_penalty
    SAVE_TESTINPUTS = args.save_inputs
    SAVE_TESTCASES = args.save_tests

    if args.verbose:
        LOGGER.setLevel(logging.DEBUG)

    is_c = args.file[-2:] == '.c'
    is_i = args.file[-2:] == '.i'
    is_source = is_c or is_i

    if is_source:
        source = args.file
        stem = source[:-2]
        BINARY = stem+'.instr'
        LOGGER.info('Building {}'.format(BINARY))
        os.system("make {}".format(BINARY))
        # print("./trace-cc -static -L. -legion -o {} {}".format(BINARY,source))
        # os.system("./trace-cc -static -L. -legion -o {} {}".format(BINARY,source))
    else:
        BINARY = args.file

    binary_name = BINARY.split("/")[-1]
    DIR_NAME = "{}_{}_{}_{}".format(
        binary_name, MIN_SAMPLES, TIME_COEFF, TIME_START)

    if is_source and SAVE_TESTCASES:
        os.system("mkdir -p tests/{}".format(DIR_NAME))
        with open("tests/{}/metadata.xml".format(DIR_NAME), "wt") as md:
            md.write('<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
            md.write('<!DOCTYPE test-metadata PUBLIC "+//IDN sosy-lab.org//DTD test-format test-metadata 1.1//EN" "https://sosy-lab.org/test-format/test-metadata-1.1.dtd">\n')
            md.write('<test-metadata>\n')
            md.write('<sourcecodelang>C</sourcecodelang>\n')
            md.write('<producer>Legion</producer>\n')
            md.write('<specification>CHECK( LTL(G ! call(__VERIFIER_error())) )</specification>\n')
            md.write('<programfile>{}</programfile>\n'.format(args.file))
            res = sp.run(["sha256sum", args.file], stdout=sp.PIPE)
            out = res.stdout.decode('utf-8')
            sha256sum = out[:64]
            md.write('<programhash>{}</programhash>\n'.format(sha256sum))
            md.write('<entryfunction>main</entryfunction>\n')
            md.write('<architecture>32bit</architecture>\n')
            md.write('<creationtime>{}</creationtime>\n'.format(datetime.datetime.now()))
            md.write('</test-metadata>\n')

    SEEDS = args.seeds

    # profile.run('run()')
    run()
    ROOT.pp()
