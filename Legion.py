import enum
import logging
import os
import pdb
import random
import struct
import subprocess as sp
import sys
import time
from typing import Dict, List

from angr import Project
from angr.sim_state import SimState as State
from angr.storage.file import SimFileStream
from math import sqrt, log, ceil, inf

# Hyper-parameters
MIN_SAMPLES = int(sys.argv[1])
MAX_SAMPLES = 100
TIME_COEFF = float(sys.argv[2])
RHO = 1 / sqrt(2)

MAX_BYTES = 100  # Max bytes per input

# Budget
MAX_PATHS = float('inf')
MAX_ROUNDS = float('inf')
FOUND_BUG = False  # type: bool

# Statistics
CUR_ROUND = 0
TIME_START = time.time()

# Execution
BINARY = sys.argv[3]
SEEDS = sys.argv[4:]
BUG_RET = 100  # the return code when finding a bug

# cache Node
# ROOT = TreeNode()  # type: TreeNode or None

# Logging
LOGGER = logging.getLogger("Legion")
LOGGER.setLevel(logging.DEBUG)
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
    Colour | Tracejump    | Angr         | Symex state
    White  | True         | Undetermined | Undetermined
    Red    | True         | True         | False, stored in its simulation child
    Gold   | False        | False        | True, stores its parent's state
    Black  | True         | False        | False
    Purple | Undetermined | True         | True, stores its own state
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
        assert self.colour is Colour.W
        # All colours should come with a state, except black
        assert bool(colour is Colour.B) ^ bool(state)

        self.colour = colour
        if colour is Colour.R:
            # No pre-existing simulation child
            assert 'Simulation' not in self.children
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
        if self.state.solver.constraints:
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
                self.fully_explored = True
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
        assert (key == 'Simulation') ^ (key == new_child.addr)
        self.children[key] = new_child

    def match_child(self, addr: int) -> bool:
        """
        Check if the addr matches to an existing child:
            if not, it corresponds to a new path, add the addr as a child
        :param addr: the address to check
        :return: if the addr corresponds to a new path
        """
        # check if the addr corresponds to a new path
        is_new = addr not in self.children
        if is_new:
            self.add_child(key=addr, new_child=TreeNode(addr=addr, parent=self))
        return is_new

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
        if indent > 15 and self.parent and self.parent.colour is 'W':
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
        ROOT.pp()


def initialisation():
    def init_angr():
        return Project(BINARY)

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


def has_budget() -> bool:
    """
    Control whether to terminate mcts or not
    :return: True if terminate
    """
    return ROOT.sim_win < MAX_PATHS and CUR_ROUND < MAX_ROUNDS \
           and not ROOT.fully_explored


def mcts():
    """
    The four steps of MCTS
    """
    node = selection()
    traces = simulation(node=node)
    are_new = expansion(traces=traces)
    assert len(traces) == len(are_new)
    propagation(node=node, traces=traces, are_new=are_new)


def selection() -> TreeNode:
    """
    Repeatedly apply tree policy until a simulation node is selected
    # :param node: the node to start selection on
    :return: nodes along the selection path
    """
    node = ROOT
    while node.colour is not Colour.G:
        node = tree_policy(node=node)

    assert node.colour is Colour.G
    return node


def tree_policy(node: TreeNode) -> TreeNode:
    """
    Select the best child of the node
    dye the node if it is white
    :param node: the node to select child from
    :return: the child selected
    """
    if node.colour is Colour.W:
        untraced_states = dye_siblings(parent=node.parent)
        add_children(parent=node.parent, states=untraced_states)
    return node.best_child()


def dye_siblings(parent: TreeNode) -> List[State]:
    """
    If a child of the parent is found white, then all children of the parent must also be white;
    This function dyes them all.
    :param parent: the parent of the white child
    :return: a list of states that do not match with any of the existing children of the parent,
                they correspond to the child nodes of the parent who have not been found by TraceJump
    """
    parent_state = parent.children['Simulation'].state
    child_states = compute_to_diverge(state=parent_state)

    for child_node in parent.children.values():
        if child_node.colour is Colour.G:
            continue
        child_states = match_node_states(node=child_node, states=child_states)
        if child_node.colour is not Colour.R:
            pdb.set_trace()
        assert child_node.colour is Colour.R
    return child_states


def compute_to_diverge(state: State):
    """
    Symbolically execute to the immediate next diverging states and return its children (must be more than one)
    :param state: the state which is in the line to execute through
    :return: a list of the immediate child states of the line,
        could be empty if the line is a leaf
    """
    child_states = symex(state=state)
    while len(child_states) == 1:
        print(child_states)
        if len(child_states[0].solver.constraints) > len(
                state.solver.constraints):
            break
        child_states = symex(state=child_states[0])

    return child_states


def symex(state: State) -> List[State]:
    """
    One step of symbolic execution from state
    :param state: the state to execute from
    :return: the resulting state(s) of symbolic execution
    """
    return state.step().successors


def match_node_states(node: TreeNode, states: List[State]) -> List[State]:
    """
    If the node matches one of the states, then dye node to red
        and remove it from the list of states

    :param node: the node to match with state
    :param states: a list of states to match with the node
    :return: a list of states that does not match with the node
    """
    for state in states:
        # try to match each state to the node
        if node.addr == state.addr:
            node.dye(colour=Colour.R, state=state)
            states.remove(state)
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
        assert state.addr not in parent.children
        parent.add_child(key=state.addr,
                         new_child=TreeNode(addr=state.addr, parent=parent))
        parent.children[state.addr].dye(colour=Colour.R, state=state)


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
    return [binary_execute(mutant) for mutant in mutants]


def binary_execute(input_bytes: bytes) -> List[int]:
    """
    Execute the binary with an input in bytes
    :param input_bytes: the input to feed the binary
    :return: the execution trace in a list
    """

    def unpack(output):
        assert (len(output) % 8 == 0)
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
            exit(2)

    global FOUND_BUG
    report = execute()
    if not report:
        pdb.set_trace()

    report_msg, return_code = report
    error_msg = report_msg[1]
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
    assert trace[0] == ROOT.addr

    node, is_new = ROOT, False
    for addr in trace[1:]:
        is_new = node.match_child(addr=addr) or is_new
        node = node.children[addr]
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
        assert trace[0] == ROOT.addr
        node = ROOT
        record_simulation(node=node, new=is_new)
        for addr in trace[1:]:
            node = node.children[addr]
            record_simulation(node=node, new=is_new)

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

    assert len(traces) == len(are_new)
    for i in range(len(traces)):
        propagate_execution_trace(trace=traces[i], is_new=are_new[i])


if __name__ == '__main__':
    run()
