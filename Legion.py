#!/usr/bin/env python3

import sys
import argparse
import cProfile
import datetime
import enum
import gc
import logging
import os
# import pdb
import random
import signal
import struct
import subprocess as sp
import time
from math import sqrt, log, ceil, inf
# from memory_profiler import profile
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Tuple
from types import GeneratorType

from angr import Project
from angr.sim_state import SimState as State
from angr.storage.file import SimFileStream
from angr.sim_options import LAZY_SOLVES
from z3.z3types import Z3Exception

VERSION = "0.1-testcomp2020"

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--version':
        print(VERSION)
        sys.exit(0)


# Hyper-parameters
MIN_SAMPLES = 3
MAX_SAMPLES = 100
TIME_COEFF = 0
RHO = 1 / sqrt(2)
RAN_SEED = None
SYMEX_TIMEOUT = 0  # in secs
CONEX_TIMEOUT = None  # in secs
MAX_BYTES = 1000  # Max bytes per input
TREE_DEPTH_LIMIT = 100000000   # INT_MAX is 2147483647, a large value will cause a compilation error

# Budget
MAX_PATHS = float('inf')
MAX_ROUNDS = float('inf')
CORE = 1
SIMPOOL = None
MAX_TIME = 0
FOUND_BUG = False  # type: bool
COVERAGE_ONLY = False
PERSISTENT = False

# Statistics
CUR_ROUND = 0
TIME_START = time.time()
SEED_IN_COUNT = 0
SOL_GEN_COUNT = 0
FUZ_GEN_COUNT = 0
RND_GEN_COUNT = 0
SYMEX_TIMEOUT_COUNT = 0
CONEX_TIMEOUT_COUNT = 0
SYMEX_TIME = 0
CONEX_TIME = 0
SYMEX_SUCCESS_COUNT = 0
CONEX_SUCCESS_COUNT = 0
MIN_TREE_DEPTH = inf
MAX_TREE_DEPTH = 0
SUM_TREE_DEPTH = 0


COLLECT_STATISTICS = False

# Execution
INSTR_BIN = None
DIR_NAME = None
SEEDS = []
BUG_RET = 100  # the return code when finding a bug
SAVE_TESTINPUTS = None
SAVE_TESTCASES = None
DEFAULT_ADDR = -1

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
logging.getLogger('angr').setLevel('ERROR')

SCORE_FUN = 'uct'


# Colour of tree nodes
class Colour(enum.Enum):
    W = 'White'
    R = 'Red'
    G = 'Gold'
    B = 'Black'
    P = 'Purple'


# TreeNode:
class TreeNode:
    """
    Colour | TraceJump    | ANGR         | Symex state
    White  | True         | Undetermined | Undetermined
    Red    | True         | True         | False, stored in its simulation child
    Gold   | False        | False        | True, stores its parent's state
    Black  | True         | no sibling   | True if is intermediate, False if is leaf
    Purple | False        | True         | True, only showed up in ANGR, not found by TraceJump
    """

    def __init__(self, addr: int = DEFAULT_ADDR, parent: 'TreeNode' = None,
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
        self.exhausted = False

    def child(self, name) -> 'TreeNode' or None:
        """
        Get the child whose hex(addr) matches with the name
        :param name: the hex(addr) of the child
        :return: the matching child
        """
        for child in self.children.values():
            if hex(child.addr)[-len(name):] == name:
                return child
        return None

    def sim_state(self) -> State or None:
        """
        SimStates of red nodes are stored in their simualtion child
        SimStates of white nodes are None
        SimStates of black/gold nodes are stored in them
        :return: the symbolic state of the node
        """
        if self.colour is Colour.R:
            return self.children['Simulation'].state
        return self.state

    def constraints(self) -> List:
        """
        :return: the path constraints of the node/state
        """
        return self.sim_state().solver.constraints \
            if self.sim_state() else "No SimState"

    def exploit_score(self) -> float:
        # Evaluate to maximum value if not tried before
        if not self.sel_try:
            return inf
        return self.sim_win / self.sel_try

    def explore_score(self) -> float:
        # If the exploration ratio rho is 0, then return 0
        if RHO == 0:
            return 0
        # Evaluate to maximum value if is root
        if self.is_root():
            return inf
        # Evaluate to maximum value if not tried before
        if not self.sel_try:
            return inf
        return sqrt(2 * log(self.parent.sel_try) / self.sel_try)

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
        if self.is_fully_explored():
            return -inf

        if self.colour is Colour.G and len(self.parent.children) > 1 \
                and len([child for child in self.parent.children.values()
                         if child is not self and child.score() > -inf]) == 1:
            return -inf

        if SCORE_FUN == 'random':
            score = random.uniform(0, 100)
        else:
            debug_assertion(SCORE_FUN == 'uct')
            uct_score = self.exploit_score() + 2 * RHO * self.explore_score()
            score = uct_score - TIME_COEFF * time_penalisation() \
                if TIME_COEFF else uct_score

        return score

    def is_fully_explored(self):
        if PERSISTENT:
            if ROOT.fully_explored and self is not ROOT:
                return (self.is_leaf() and self.colour is not Colour.G) \
                       or self.exhausted
        return self.fully_explored

    def mark_fully_explored(self):
        """
        Mark a node fully explored
        If the node is simulation node, mark its parent fully explored
        If the node is red, mark its simulation child fully explored
        If all block siblings are fully explored, mark its parent fully explored
        :return:
        """

        if self.colour is Colour.W:
            # White node might have an unrevealed sibling
            #   which can only be found by symex it
            return

        if not all([c.is_fully_explored() for c in self.children.values()
                    if c.colour is not Colour.G]):
            # If not all children all fully explored, don't mark it
            #    exclude simulation child here.
            return

        # if not self.sel_try and self.colour is Colour.R:
        if self.phantom:
            # This line makes sure that we will simulate on every phantom node
            # at least once to discover the path beneath them:
            #   1. Black nodes cannot be a phantom, cause phantoms must have
            #       a sibling (phantoms are found when symex to their siblings).
            #   2. Gold nodes do not have any sibling before the first
            #       execution, it will be picked even if it is fully explored.
            #   3. Red nodes should not be marked fully explored before
            #       testing out at once, in case it is a phantom
            return

        LOGGER.info("Mark fully explored {}".format(self))
        self.fully_explored = True

        # if self.colour is Colour.G:
        #     self.parent.is_fully_explored() = True

        if self.colour is Colour.R and self is not ROOT:
            LOGGER.info("Red parent Fully explored {}".format(self.children['Simulation']))
            self.children['Simulation'].fully_explored = True

        if self.parent:
            self.parent.mark_fully_explored()

    def best_child(self) -> 'TreeNode':
        """
        Select the child of the highest uct score, break tie uniformly
        :return: a tree node
        """

        LOGGER.info("Selecting from children: {}".format(self.children))
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

        return random.choice(candidates) if candidates else None

    def is_root(self) -> bool:
        """
        All node except the root should have a parent
        :return: if the node is root
        """
        return not self.parent

    def is_leaf(self) -> bool:
        """
        If the node has no other child than simulation node,
         and it is not a phantom. then it is a leaf
        :return: whether the node is a leaf
        """
        no_child_or_only_gold = not self.children \
                                or all([child.colour == Colour.G
                                        for child in self.children.values()])
        return not self.phantom and no_child_or_only_gold

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
        debug_assertion(bool(colour is Colour.B) or bool(state))

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
        if self.state and self.state.solver.constraints:
            results = self.app_fuzzing()
            return results
        return self.random_fuzzing()

    def app_fuzzing(self) -> List[Tuple[bytes, str]]:
        def byte_len() -> int:
            """
            The number of bytes in the input
            :return: byte length
            """
            return (target.size() + 7) // 8

        # Note: Once we fuzz a simulation child,
        #   its parent is no longer a phantom
        #   This is important as we do not mark phantom fully explored
        self.parent.phantom = False
        target = self.state.posix.stdin.load(0, self.state.posix.stdin.size)
        results = []

        if not self.samples:
            self.samples = self.state.solver.iterate(target)
            if type(self.samples) is not GeneratorType:
                # Note: self.samples might not be an iterator in some cases
                #   e.g. when solving for the wrong thing
                #   which happened before when the constraint is solving for the
                #   number of args
                self.exhausted = True
                self.fully_explored = True
                return results

        # Denotes the generation method for each input
        # S: constraint solving; F: fuzzing; R: random generation
        method = "S"
        while len(results) < MAX_SAMPLES:
            try:
                val = next(self.samples)
                if val is None and len(results) >= MIN_SAMPLES:
                    # next val requires constraint solving and enough results
                    break
                if val is None and len(results) < MIN_SAMPLES:
                    # requires constraint solving but not enough results
                    method = "S"
                    continue
                result = (val.to_bytes(byte_len(), 'big'), method)
                results.append(result)
                method = "F"
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

                # Note: If the state of the simulation node is unsatisfiable
                #   then this will occur in the first time the node is selected
                LOGGER.info("Exhausted {}".format(self))
                LOGGER.info("Fully explored {}".format(self))
                self.fully_explored = True
                self.exhausted = True
                self.parent.exhausted = True
                # NOTE: In some case, no input can be found from the simul child
                #   even if its red parent is considered as feasible, weird.
                #   In this case, parent.sel_try is 0, which prevents it to
                #   be marked as fully explored with
                #   self.parent.mark_fully_explored()
                # block_sibs = [c for c in self.parent.children.values()
                #               if c.colour is not Colour.G]
                # if not block_sibs:
                #     self.parent.is_fully_explored() = True
                # Note: Should not mark parent fully explored
                #   as 1) there may be a path although no input was found
                #      2) this exception occurs when NO ENOUGH inputs were found
                #         which does not imply no input was found
                #         here there could be a child to be selected in the
                #         next iteration
                # self.parent.mark_fully_explored()
                break
        return results

    @staticmethod
    def random_fuzzing() -> List[Tuple[bytes, str]]:
        def random_bytes():
            LOGGER.debug("Generating random {} bytes".format(MAX_BYTES))
            # input_bytes = b''
            # for _ in range(MAX_BYTES):
            #     input_bytes += os.urandom(1)
            # return input_bytes
            # Or return end of file char?
            return os.urandom(MAX_BYTES)
        return [(random_bytes(), "R") for _ in range(MIN_SAMPLES)]

    def add_child(self, key: str or int, new_child: 'TreeNode') -> None:
        debug_assertion((key == 'Simulation') ^ (key == new_child.addr))
        self.children[key] = new_child

    def match_child(self, addr: int) -> Tuple[bool, 'TreeNode']:
        """
        Check if the addr matches to an existing child:
            if not, it corresponds to a new path, add the addr as a child
        :param addr: the address to check
        :return: if the addr corresponds to a new path
        """
        # check if the addr corresponds to a new path:
        # Note: There are two cases for addr to be new:
        #   1. addr is a phantom child
        #   2. addr is not a child of self

        child = self.children.get(addr)

        if child:
            is_phantom = child.phantom
            child.phantom = False
            return is_phantom, child

        child = TreeNode(addr=addr, parent=self)
        self.add_child(key=addr, new_child=child)
        return True, child

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
            + 2 * RHO * sqrt(2 * log(self.parent.sel_try) / self.self_try)
        :return:
        """
        return "{uct:.2f} = {explore:.2f}({simw}/{selt}) " \
               "+ {exploit:.2f}(sqrt(log({pselt})/{selt})" \
            .format(uct=self.score(),
                    explore=self.exploit_score(),
                    exploit=self.explore_score(),
                    simw=self.sim_win,
                    selt=self.sel_try,
                    pselt=self.parent.sel_try if self.parent else None,
                    simt=self.sim_try)
        # return "{uct:.2f} = {simw}/{selt} " 1\
        #        "+ 2*{r:.2f}*sqrt(log({pselt})/{simt}) " \
        #        "- {t:.2f}*{at:.2f}/({selt}+log({MS}, 2)-1)/{MS}*2^{selt})" \
        #     .format(uct=self.score(), simw=self.sim_win, selt=self.sel_try,
        #             r=RHO, pselt=self.parent.sel_try if self.parent else inf,
        #             simt=self.sim_try,
        #             t=TIME_COEFF, at=self.accumulated_time, MS=MIN_SAMPLES)

    def repr_node_state(self) -> str:
        return "{}".format(self.sim_state()) if self.sim_state() else "NoState"

    def __repr__(self) -> str:
        return '\033[1;{colour}m{name}: {data}, {state}\033[0m' \
            .format(colour=30 if self.colour is Colour.B else
                    35 if self.phantom else
                    31 if self.colour is Colour.R else
                    33 if self.colour is Colour.G else
                    37 if self.colour is Colour.W else 32,
                    name=self.repr_node_name(),
                    state=self.repr_node_state(),
                    data=self.repr_node_data())


ROOT = TreeNode()


def consider_tree_fully_explored() -> bool:
    return ROOT.is_fully_explored() and not PERSISTENT


def run() -> None:
    """
    The main function
    """
    initialisation()
    ROOT.pp()
    while has_budget():
        mcts()


def initialisation():
    def init_angr():
        LOGGER.info("Initialising ANGR Project")
        return Project(thing=INSTR_BIN,
                       ignore_functions=['printf',
                                         '__trace_jump',
                                         '__trace_jump_set'
                                         ],
                       )

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

        # Assert all traces start with the same address (i.e. main())
        firsts = [trace for trace in zip(*traces)][0]

        # Note: Relies on the first trace being correct at all times.
        main_addr = -1
        for first in firsts:
            if first == DEFAULT_ADDR:
                # Having the DEFAULT_ADDR means binary execution did not find a meaningful address
                continue
            main_addr = first
        # debug_assertion(main_addr != DEFAULT_ADDR)
        if main_addr != DEFAULT_ADDR:
            # NOTE: a meaningful address for root has been found
            # Jump to the state of main_addr
            project = init_angr()

            # Noted: Tested angr on symbolic argc, failed
            # main_state = project.factory.entry_state(
            #     addr=main_addr,
            #     stdin=SimFileStream,
            #     argc=claripy.BVS('argc', 100*8)
            # )
            main_state = project.factory.blank_state(addr=main_addr,
                                                     stdin=SimFileStream,
                                                     add_options={LAZY_SOLVES}
                                                     )
        else:
            # Switch to random fuzzing
            main_state = None
            # sp.run([args.cc, "-no-pie", "-O0", "-o", INSTR_BIN, verifier_c, "__VERIFIER_assume.c", source])

        root = TreeNode(addr=main_addr)
        root.dye(colour=Colour.R, state=main_state)
        LOGGER.info("ROOT created")
        return root

    global ROOT
    LOGGER.info("Simulating on the seeded inputs")
    traces, test_cases, test_inputs = simulation(node=None)
    LOGGER.info("Initialising the ROOT")
    ROOT = init_root()
    LOGGER.info("Expanding the tree with paths taken by seeded inputs")
    are_new = expansion(traces=traces)
    LOGGER.info("Propagating the first results")
    propagation(node=ROOT.children['Simulation'], traces=traces,
                are_new=are_new)
    save_results_to_files(test_cases, test_inputs, are_new)


def has_budget() -> bool:
    """
    Control whether to terminate mcts or not
    :return: True if terminate
    """
    return not FOUND_BUG \
           and not consider_tree_fully_explored() \
           and ROOT.sim_win < MAX_PATHS \
           and CUR_ROUND < MAX_ROUNDS


def mcts():
    """
    The four steps of MCTS
    """
    node = selection()
    if node is ROOT:
        return
    traces, test_cases, test_inputs = simulation(node=node)
    are_new = expansion(traces=traces)
    debug_assertion(len(traces) == len(are_new))
    propagation(node=node, traces=traces, are_new=are_new)
    ROOT.pp(mark=node, found=sum(are_new))
    save_results_to_files(test_cases, test_inputs, are_new)


def selection() -> TreeNode:
    """
    Repeatedly apply tree policy until a simulation node is selected
    # :param node: the node to start selection on
    :return: nodes along the selection path
    """

    # def dye_node(target: TreeNode) -> List[State]:
    #     """
    #     Since the target is white, dye it and its siblings
    #     :param target: the node to dye
    #     :return: the states left after dying (i.e. because the node is black)
    #     """
    #     # states = dye_siblings(child=target)
    #     #
    #     # if target.colour is Colour.R:
    #     #     # Add the states left as phantom child of the target's parent
    #     #     add_children(parent=target.parent, states=states)
    #     #     # NOTE: if the node is dyed to red,
    #     #     #  it means all states left must belong to its siblings
    #     #     states = []
    #     # return states

    def reach_symex_timeout() -> bool:
        LOGGER.info("symex time available: {}/{}".format(symex_time, SYMEX_TIMEOUT))
        return SYMEX_TIMEOUT and symex_time >= SYMEX_TIMEOUT

    global SYMEX_TIME, SYMEX_TIMEOUT_COUNT, SYMEX_SUCCESS_COUNT

    symex_time = 0
    last_red = ROOT
    node = ROOT
    selection_start_time = time.time()
    while node.colour is not Colour.G:
        if node.colour is Colour.R:
            last_red = node
        # Note: Must check this before dying,
        #  otherwise the phantom red nodes which are added when
        #  dying their sibling will be wrongly marked as fully explored
        if node.is_leaf() and node.colour is Colour.B:
            # NOTE: a red/white leaf may have unknown siblings
            node.mark_fully_explored()

        # If the node is white, dye it
        if node.colour is Colour.W:
            dye_start_time = time.time()
            try:
                dye_siblings(child=node)  # Upon an exception, mark this node fully explored
            except Z3Exception:
                LOGGER.info("Z3 exception occurred in symex, any type casting in program")
                node.fully_explored = True
                node.exhausted = True
                node.parent.mark_fully_explored()
            symex_time += time.time() - dye_start_time

            # # IF the node is dyed to black and there is no states left,
            # # it implies the previous parent state does not have any diverging
            # # descendants found by `compute_to_diverging()`, hence the rest of the
            # # tree must be fully explored, and there is no difference in fuzzing
            # # any of them
            # if node.colour is Colour.B and not states_left:
            #     LOGGER.info("Fully explored {}".format(node))
            #     node.is_fully_explored() = True

        if reach_symex_timeout():
            LOGGER.info(
                "Symex timeout, choose the simulation child of the last red {}".format(last_red))
            node = last_red.children['Simulation']
            SYMEX_TIMEOUT_COUNT += 1
            if COLLECT_STATISTICS:
                print("SYMEX_TIMEOUT count: {}".format(SYMEX_TIMEOUT_COUNT))
            break

        if node.is_leaf():
            LOGGER.info("Leaf reached before tree policy: {}".format(node))
            LOGGER.info("Fully explored {}".format(node))
            node.fully_explored = True
            if node.parent:
                # NOTE: the if condition above makes sure there is parent to set
                #   the check is trivial in most cases
                #   but handles the case when the ROOT is a leaf
                #   e.g. the program crashes right after entry because of allocating too much memory
                node.parent.mark_fully_explored()

        # If the node's score is the minimum, return ROOT to restart
        if node.is_fully_explored() and node is not ROOT:
            return ROOT

        node = tree_policy(node=node)

        if node.is_leaf() and node.colour is Colour.R:
            # Note: There is no point fuzzing a red leaf,
            #   as it will not have any child
            #   (assuming no trace is a prefix of another)
            #   Mark the red leaf fully explored and check its parent
            #   restart the selection from ROOT
            LOGGER.info("Leaf reached after tree policy: {}".format(node))
            LOGGER.info("Fully explored {}".format(node))
            node.fully_explored = True
            node.parent.mark_fully_explored()

        if node.is_fully_explored():
            # NOTE: If, for some reason, the node selected if fully explored
            #   then we ASSUME its parent is fully explored
            #   but not correctly marked as fully explored
            #   return ROOT to re-launch selection stage
            # pdb.set_trace()
            if ROOT.fully_explored and node.parent:
                node.parent.exhausted = True
            node.parent.mark_fully_explored()
            return ROOT
        # the node selected by tree policy should not be None
        debug_assertion(node is not None)
        LOGGER.info("Select: {}".format(node))

    debug_assertion(node.colour is Colour.G)

    selection_end_time = time.time()
    SYMEX_TIME += (selection_end_time - selection_start_time)
    SYMEX_SUCCESS_COUNT += 1
    if COLLECT_STATISTICS:
        print("SYMEX_TIME: {:.4f}".format(SYMEX_TIME))
        print("SYMEX_SUCCESS count: {}".format(SYMEX_SUCCESS_COUNT))
        print("SYMEX_TIME_AVG: {:.4f}".format(SYMEX_TIME / SYMEX_SUCCESS_COUNT))
    return node


def tree_policy(node: TreeNode) -> TreeNode:
    """
    Select the best child of the node
    :param node: the node to select child from
    :return: the child selected
    """
    return node.best_child()


def dye_siblings(child: TreeNode) -> None:
    """
    If a child of the parent is found white,
    then all children of the parent must also be white;
    This function dyes them all.
    :param child: the node to match
    :return: a list of states that
            do not match with any of the existing children of the parent,
            they correspond to the child nodes of the parent who
            have not been found by TraceJump
    """
    #
    # # Case 1: parent is red, then execute parent's state to find states of sibs
    # # Case 2: parent is black, use the states left to dye siblings
    # # Either 1 or 2, not both
    # debug_assertion((parent.colour is Colour.R) ^ bool(target_states))

    # if child.parent.colour is Colour.R:
    #     debug_assertion(not target_states)
    #     parent_state = parent.children['Simulation'].state
    #     target_states = symex_to_match(state=parent_state, addr=child.addr)
    #
    #     # NOTE: Empty target states implies
    #     #  the symbolic execution has reached the end of program
    #     #  without seeing any divergence after the parent's state
    #     #  hence the parent is fully explored
    #     # Note: a single target state does not mean the parent is fully explored
    #     #   It may be the case where the target is the only feasible child,
    #     #   but the target has other diverging child states
    #     if not target_states:
    #         pdb.set_trace()
    #         parent.is_fully_explored() = True

    sibling_states = symex_to_match(target=child)

    # Note: dye child according to the len of sibling_states:
    #   1. len is 0, the child's parent must have been fully explored.
    #   2. len is 1, the child should be dyed black, as it is the only feasible child
    #   3. len >= 2, the child should be dyed red, add phantom if needed

    if not sibling_states:
        # No state is found, no way to explore deeper on this path
        # Ideally, no diverging tree node should exist beneath the parent of the child.
        # hence mark the child fully explored, and trace back to ancestors
        LOGGER.info("No state found: {}".format(child))
        # if hex(child.addr)[-4:] == '0731':
        #     pdb.set_trace()
        child.fully_explored = True
        child.parent.mark_fully_explored()

    if len(sibling_states) == 1:
        state = sibling_states.pop()
        # This should only happen if the only state in sibling_states matches with the child
        debug_assertion(child.addr == state.addr)
        # No gold node for black nodes, hence no simulation will start from black ones
        # No sibling node for black ndoes, hence they will never be compared with other nodes,
        # except parent's simulation child.
        child.dye(colour=Colour.B, state=state)

    if len(sibling_states) > 1:
        # For each state in siblings_states:
        #   if it can match with an existing child, then dye the child red with the state
        #   otherwise create a phantom child with the state
        for state in sibling_states:
            matched = match_node_states(
                state=state,
                children=[node for node in child.parent.children.values()
                          if node.colour is not Colour.G])

            if not matched:
                add_phantom(parent=child.parent, state=state)

        debug_assertion(all(sibling.colour is Colour.R
                            for sibling in child.parent.children.values()
                            if sibling.colour is not Colour.G))

        # # A way to save mem
        # if child.parent.colour is Colour.B:
        #     debug_assertion(bool(child.parent.state))
        #     child.parent.state = None

        # for child_node in child.parent.children.values():
        #     if child_node.colour is Colour.G:
        #         continue
        #     sibling_states = match_node_states(node=child_node, state=sibling_states)
        #     debug_assertion(child_node.colour is Colour.R)


def symex_to_match(target: TreeNode) -> List[State]:
    """
    Symbolically execute from the parent of the target
    to the immediate next state whose address matches withthe target (may have siblings)
    :param target: the target to match against
    :return: a list of the immediate child states of the line,
        could be empty if the line is a leaf
        could be one if the addr is the only feasible child
        could be more if the addr has other feasible siblings
    """
    child_states = symex(state=target.parent.sim_state())

    while child_states and target.addr not in [state.addr for state in child_states]:
        # If there are at least two child states,
        # then the the target address should have matched with one of the states
        debug_assertion(len(child_states) == 1)
        child_states = symex(state=child_states[0])

    if not child_states:
        LOGGER.info("Symbolic execution reached the end of the program")

    return child_states


def symex_to_addr(target: TreeNode, addr: int) -> List[State]:
    """
    Symbolically execute from the parent of the target
    to the immediate next state whose address matches withthe target (may have siblings)
    :param target: the target to match against
    :param addr: the address to match
    :return: a list of the immediate child states of the line,
        could be empty if the line is a leaf
        could be one if the addr is the only feasible child
        could be more if the addr has other feasible siblings
    """
    child_states = symex(state=target.sim_state())

    while child_states and addr not in [state.addr for state in child_states]:
        # If there are at least two child states,
        # then the the target address should have matched with one of the states
        debug_assertion(len(child_states) == 1)
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
    # Note: Need to keep all successors?
    LOGGER.debug("computing successors for {}".format(state))
    if state is None:
        LOGGER.debug("No corresponding state found, any dynamic array allocation in the code?")
        return []
    successors = state.step().successors
    LOGGER.debug("Successors are: {}".format(successors))
    return successors


def match_node_states(state: State, children: List[TreeNode]) -> bool:
    """
    If the node matches one of the states, then dye node to red
        and remove it from the list of states
    Else dye the node to black
    :param state: a state to match with one of the children
    :param children: a list of node to match with state
    :return: the successfulness of matching
    """
    # if not states:
    #     node.dye(colour=Colour.B)
    #     # NOTE: Empty target states implies
    #     #  the symbolic execution has reached the end of program
    #     #  without seeing any divergence after the parent's state
    #     #  hence the parent is fully explored
    #     node.mark_fully_explored()
    #     return states
    matched = False
    for child in children:
        # try to match each state to the node
        if child.addr != state.addr:
            continue
        child.dye(colour=Colour.R, state=state)
        matched = True
        break
    # if node.colour is Colour.W:
    #     node.dye(colour=Colour.B)

    return matched


def add_phantom(parent: TreeNode, state: State) -> None:
    """
    Given all states that do not match with any of the parent's child nodes,
    it implies those nodes have not been discovered by TraceJump.
    The nodes must be there, we might as well add them directly
    :param parent: the parent to which the child nodes will be added
    :param state: the state of the phantom node
    :return:
    """
    debug_assertion(state.addr not in parent.children)
    parent.add_child(key=state.addr,
                     new_child=TreeNode(addr=state.addr, parent=parent))
    parent.children[state.addr].dye(colour=Colour.R, state=state)
    parent.children[state.addr].phantom = True
    LOGGER.info("Add Phantom {} to {}".format(state, parent))


def simulation(node: TreeNode = None) \
        -> Tuple[List[List[int]], List[Tuple[float, str, str]], List[Tuple[float, bytes, str]]]:
    """
    Generate mutants (i.e. inputs that tend to preserve the path to the node)
    Execute the instrumented binary with mutants to collect the execution traces
    :param node: the node to fuzz
    :return: the execution traces
    """
    # node is None if this is initialisation, during which should:
    #   use SEEDS if SEEDS is available or use random fuzzing if not
    # otherwise, mutate() the node

    global FOUND_BUG, MSGS, INPUTS, TIMES
    mutants = node.mutate() if node else \
        [(bytes("".join(mutant), 'utf-8'), "D")
         # Note: Need to make sure the first binary execution must complete successfully
         #  Otherwise (e.g. timeout) the root address will be wrong
         for mutant in SEEDS] if SEEDS else ([(b'\x00'*MAX_BYTES, "D")])

    # Set the inital input to be a EoF char?

    global SIMPOOL
    SIMPOOL = Pool(processes=CORE) if (CORE > 1 and not SIMPOOL) else None
    if SIMPOOL:
        results = SIMPOOL.map(binary_execute_parallel, mutants)
    else:
        results = [binary_execute_parallel(mutant)
                   for mutant in mutants if not FOUND_BUG]
    traces, testcases, testinputs = [], [], []
    for result in results:
        trace, curr_found_bug, testcase, testinput = result
        traces.append(trace)
        testcases.append(testcase)
        testinputs.append(testinput)
        FOUND_BUG = FOUND_BUG or curr_found_bug
    return traces, testcases, testinputs


def binary_execute_parallel(input_bytes: Tuple[bytes, str]):
    """
    Execute the binary with an input in bytes
    :param input_bytes: the input to feed the binary
    :return: the execution trace in a list
    """

    def unpack(output):
        debug_assertion((len(output) % 8 == 0))
        # NOTE: changed addr[0] to addr
        return [addr for i in range(int(len(output) / 8))
                for addr in struct.unpack_from('q', output, i * 8)]

    def execute():
        global CONEX_TIME, CONEX_TIMEOUT_COUNT, CONEX_SUCCESS_COUNT

        instr = sp.Popen(INSTR_BIN, stdin=sp.PIPE, stdout=sp.PIPE,
                         stderr=sp.PIPE, close_fds=True)
        msg = ret = None
        # 0: no timeout; 1: instrumented binary timeout; 2: uninstrumented binary timeout
        timeout = False
        start_conex = time.time()
        try:
            msg = instr.communicate(input_bytes[0], timeout=CONEX_TIMEOUT)
            ret = instr.returncode
            instr.terminate()
            del instr
            gc.collect()
            LOGGER.info("Instrumented binary execution completed")
            end_conex = time.time()
            CONEX_TIME += end_conex - start_conex
            CONEX_SUCCESS_COUNT += 1
            if COLLECT_STATISTICS:
                print("CONEX_TIME: {:.4f}".format(CONEX_TIME))
                print("CONEX_SUCCESS count: {}".format(CONEX_SUCCESS_COUNT))
                print("CONEX_TIME_AVG: {:.4f}".format(CONEX_TIME / CONEX_SUCCESS_COUNT))
        except sp.TimeoutExpired:
            if "TIMEOUT" in SAVE_TESTCASES + SAVE_TESTINPUTS:
                # Note: Once instrumented binary execution times out,
                #  execute with uninstrumented binary to save inputs
                CONEX_TIMEOUT_COUNT += 1
                if COLLECT_STATISTICS:
                    print("CONEX_TIMEOUT count: {}".format(CONEX_TIMEOUT_COUNT))
                LOGGER.error("Instrumented Binary execution time out")
                instr.kill()
                del instr
                gc.collect()
                timeout = True
                try:
                    uninstr = sp.Popen(UNINSTR_BIN, stdin=sp.PIPE, stdout=sp.PIPE,
                                       stderr=sp.PIPE, close_fds=True)
                    msg = uninstr.communicate(input_bytes[0], timeout=CONEX_TIMEOUT)
                    ret = uninstr.returncode
                    LOGGER.info("Uninstrumented binary execution completed")
                    uninstr.terminate()
                    del uninstr
                    gc.collect()
                except sp.TimeoutExpired:
                    LOGGER.error("Uninstrumented Binary execution time out")
                    uninstr.kill()
                    del uninstr
                    gc.collect()
                    # print(int.from_bytes(input_bytes[:4], 'little', signed=True))
        return msg, ret, timeout

    global SEED_IN_COUNT, SOL_GEN_COUNT, FUZ_GEN_COUNT, RND_GEN_COUNT, \
        MIN_TREE_DEPTH, MAX_TREE_DEPTH, SUM_TREE_DEPTH

    LOGGER.info("Simulating...")
    report = execute()
    debug_assertion(bool(report))

    report_msg, return_code, time_out = report
    completed = report != (None, None, True)
    traced = completed and report_msg[1]
    found_bug = False

    if input_bytes[1] == "D":
        SEED_IN_COUNT += 1
        if COLLECT_STATISTICS:
            print("Seed count: {}".format(SEED_IN_COUNT))
    elif input_bytes[1] == "S":
        SOL_GEN_COUNT += 1
        if COLLECT_STATISTICS:
            print("Solving count: {}".format(SOL_GEN_COUNT))
    elif input_bytes[1] == "F":
        FUZ_GEN_COUNT += 1
        if COLLECT_STATISTICS:
            print("Fuzzing count: {}".format(FUZ_GEN_COUNT))
    elif input_bytes[1] == "R":
        RND_GEN_COUNT += 1
        if COLLECT_STATISTICS:
            print("Random count: {}".format(RND_GEN_COUNT))

    # Record the test case
    testcase = testinput = None
    curr_time = time.time() - TIME_START
    if SAVE_TESTCASES and not time_out:
        testcase = (curr_time, report_msg[0].decode('utf-8'), ("-T" if time_out else "-C")+("-"+input_bytes[1]))
    if SAVE_TESTINPUTS:
        testinput = (curr_time, input_bytes[0], ("-T" if time_out else "-C")+("-"+input_bytes[1]))

    if time_out and "TIMEOUT" in SAVE_TESTCASES:
        save_test_to_file(curr_time, report_msg[0].decode('utf-8'), ("-T" if time_out else "-C")+("-"+input_bytes[1]))
    if time_out and "TIMEOUT" in SAVE_TESTCASES:
        save_input_to_file(curr_time, report_msg[0].decode('utf-8'), ("-T" if time_out else "-C")+("-"+input_bytes[1]))

    if return_code == BUG_RET:
        found_bug = not COVERAGE_ONLY
        LOGGER.info("\n*******************"
                    "\n***** EUREKA! *****"
                    "\n*******************\n")
    trace = unpack(report_msg[1]) if traced else None

    if not time_out:
        MAX_TREE_DEPTH = max(len(trace), MAX_TREE_DEPTH)
        if COLLECT_STATISTICS:
            print("Max tree depth:{}".format(MAX_TREE_DEPTH))
        MIN_TREE_DEPTH = min(len(trace), MIN_TREE_DEPTH)
        if COLLECT_STATISTICS:
            print("Min tree depth:{}".format(MIN_TREE_DEPTH))
        SUM_TREE_DEPTH += len(trace)
        if COLLECT_STATISTICS:
            print("Avg tree depth:{}".format(SUM_TREE_DEPTH//CONEX_SUCCESS_COUNT))

    if LOGGER.level < logging.WARNING:
        trace_log = [hex(addr) if type(addr) is int else addr for addr in (
            trace if len(trace) < 7 else trace[:3] + ['...'] + trace[-3:])] \
            if traced else []
        LOGGER.info("{} of {} addresses".format(trace_log, len(trace)))

    return (trace if trace else [ROOT.addr]), found_bug, testcase, testinput


def expansion(traces: List[List[int]]) -> List[bool]:
    """
    The expansion step of MCTS.
    Expand the search tree with each of the traces
    :param traces: the traces to be integrated into the tree
    :return: a list of booleans representing whether each trace contribute to a new path
    """
    LOGGER.info("Expansion Stage")
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

    # Note: If the node happens to be an unvisited red leaf,
    #   then it means this node is from a new path that the previous lines
    #   will miss out.
    #   This happens when the node is a newly added phantom.
    is_new = is_new or not node.sim_try
    node.sim_try = node.sim_try if node.sim_try else 1

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
    LOGGER.info("Propagation Stage")
    propagate_selection_path(node=node, are_new=are_new)
    propagate_execution_traces(traces=traces, are_new=are_new)


def propagate_selection_path(node: TreeNode, are_new: List[bool]) -> None:
    """
    Back-propagate selection counter to each node in the selection path
    :param node: the node selected in selection step
    :param are_new: whether each of the execution traces is new
    :return:
    """
    # Reward the simulation node selected for findings as well
    node.sim_win += sum(are_new)
    # node.sel_try += max(len(are_new), MIN_SAMPLES)
    while node:
        # In case no/insufficient input found on that path
        node.sel_try += max(len(are_new), MIN_SAMPLES)
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
        LOGGER.info("propagate_execution_trace")
        debug_assertion(trace[0] == ROOT.addr)
        node = ROOT
        record_simulation(node=node, new=is_new)
        for addr in trace[1:]:
            node = node.children[addr]
            record_simulation(node=node, new=is_new)

        # NOTE: mark the last node as fully explored
        #   as fuzzing it will not give any new path
        #   this assumes no trace can be a prefix of another
        #   (i.e. no [1,2,3] and [1,2,3,4]
        # node.mark_fully_explored()

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


def save_results_to_files(test_cases, test_inputs, are_new):
    debug_assertion(len(test_cases) == len(test_inputs) == len(are_new))

    for i in range(len(are_new)):
        if SAVE_TESTCASES and (are_new[i] or "FULL" in SAVE_TESTCASES):
            save_test_to_file(*test_cases[i])
        if SAVE_TESTINPUTS and (are_new[i] or "FULL" in SAVE_TESTINPUTS):
            save_input_to_file(*test_inputs[i])


def save_test_to_file(time_stamp, data, suffix):
    # if DIR_NAME not in os.listdir('tests'):
    with open('tests/{}/{}_{}{}.xml'.format(
            DIR_NAME, time_stamp, SOL_GEN_COUNT, suffix), 'wt+') as input_file:
        input_file.write(
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
        input_file.write(
            '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" "https://sosy-lab.org/test-format/testcase-1.1.dtd">\n')
        input_file.write('<testcase>\n')
        input_file.write(data)
        input_file.write('</testcase>\n')


def save_input_to_file(time_stamp, input_bytes, suffix):
    # if DIR_NAME not in os.listdir('inputs'):
    os.system("mkdir -p inputs/{}".format(DIR_NAME))

    with open('inputs/{}/{}_{}{}'.format(
            DIR_NAME, time_stamp, SOL_GEN_COUNT, suffix), 'wb+') as input_file:
        input_file.write(input_bytes)


def debug_assertion(assertion: bool) -> None:
    if LOGGER.level <= logging.INFO and not assertion:
        # pdb.set_trace()
        return
    # assert assertion


def run_with_timeout() -> None:
    """
    A wrapper for run(), break run() when MAX_TIME is reached
    """
    def raise_timeout(signum, frame):
        LOGGER.debug("Signum: {};\nFrame: {};".format(signum, frame))
        LOGGER.info("{} seconds time out!".format(MAX_TIME))
        raise TimeoutError

    assert MAX_TIME
    # Register a function to raise a TimeoutError on the signal
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after MAX_TIME
    signal.alarm(MAX_TIME)
    # signal.setitimer(signal.ITIMER_PROF, MAX_TIME, 1)
    try:
        run()
    except TimeoutError:
        pass


def main() -> int:
    """
    MAX_TIME == 0: Unlimited time budget
    MAX_TIME >  0: Time budget is MAX_TIME
    """
    if MAX_TIME:
        run_with_timeout()
    else:
        run()
    ROOT.pp()
    return ROOT.sim_win


if __name__ == '__main__':
    sys.setrecursionlimit(1000000)

    parser = argparse.ArgumentParser(description='Legion')
    parser.add_argument('--min-samples', type=int, default=MIN_SAMPLES,
                        help='Minimum number of samples per iteration')
    parser.add_argument('--max-samples', type=int, default=MAX_SAMPLES,
                        help='Maximum number of samples per iteration')
    parser.add_argument("--score", default=SCORE_FUN,
                        help='Which score function to use [uct,random]')
    parser.add_argument('--time-penalty', type=float, default=TIME_COEFF,
                        help='Penalty factor for constraints that take longer to solve')
    parser.add_argument('--rho', type=float, default=RHO,
                        help='Exploration factor (default: 1/sqrt(2))')
    parser.add_argument("--core", type=int, default=cpu_count()-1,
                        help='Number of cores available')
    parser.add_argument("--random-seed", type=int, default=RAN_SEED,
                        help='The seed for randomness')
    parser.add_argument("--tree-depth-limit", type=int, default=TREE_DEPTH_LIMIT,
                        help="The maximum depth of the tree, "
                             "controlled by the length of concrete execution traces")
    parser.add_argument("--symex-timeout", type=int, default=SYMEX_TIMEOUT,
                        help='The time limit for symbolic execution')
    parser.add_argument("--conex-timeout", type=int, default=CONEX_TIMEOUT,
                        help='The time limit for concrete binary execution')
    # parser.add_argument('--sv-comp', action="store_true",
    #                     help='Link __VERIFIER_*() functions, *.i files implies --source')
    # parser.add_argument('--source', action="store_true",
    #                     help='Input file is C source code (implicit for *.c)')
    # parser.add_argument('--cc',
    #                     help='Specify compiler binary')
    # parser.add_argument('--as',
    #                     help='Specify assembler binary')
    parser.add_argument('--coverage-only', action="store_true",
                        help="Do not terminate when capturing a bug")
    parser.add_argument('--persistent', action="store_true",
                        help="Keep fuzzing even if it thinks "
                             "the tree is fully explored")
    parser.add_argument('--collect-statistics', action="store_true",
                        help="Collect the performance statistics, "
                             "e.g. conex time")
    parser.add_argument('--save-inputs', default=None, action='append',
                        choices=["FULL", "TIMEOUT", "REDUCED"],
                        help='Save inputs as binary files.'
                             'FULL: All inputs that did not trigger timeout;'
                             'REDUCED: Inputs that found new paths without timeout;'
                             'TIMEOUT: Inputs that triggered timeout;'
                             'No flag: No input;')
    parser.add_argument('--save-tests', default=None, action='append',
                        choices=["FULL", "TIMEOUT", "REDUCED"],
                        help='Save inputs as TEST-COMP xml files, [FULL, REDUCED, NONE]'
                             'FULL: All inputs that did not trigger timeout;'
                             'REDUCED: Only the inputs that found new paths without timeout;'
                             'TIMEOUT: Inputs that triggered timeout;'
                             'No flag: No input;')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='Increase output verbosity')
    parser.add_argument("-o", default=None,
                        help='Binary file output location when input is a C source')
    parser.add_argument("--cc", default="cc",
                        help='C compiler to use together with --compile svcomp')
    parser.add_argument("--compile", default="make",
                        help='How to compile C input files')
    parser.add_argument("file",
                        help='Binary or source file')
    parser.add_argument("-64", dest="m64", action="store_true",
                        help='Compile with -m64 (override platform default)')
    parser.add_argument("-32", dest="m32", action="store_true",
                        help='Compile with -m32 (override platform default)')
    parser.add_argument("--seeds", nargs='*',
                        help='Optional input seeds')

    args = parser.parse_args()

    MIN_SAMPLES = args.min_samples
    MAX_SAMPLES = args.max_samples
    CORE = args.core
    RAN_SEED = args.random_seed
    SYMEX_TIMEOUT = args.symex_timeout
    CONEX_TIMEOUT = args.conex_timeout
    TREE_DEPTH_LIMIT = args.tree_depth_limit
    COVERAGE_ONLY = args.coverage_only
    PERSISTENT = args.persistent
    TIME_COEFF = args.time_penalty
    SCORE_FUN = args.score
    RHO = args.rho
    COLLECT_STATISTICS = args.collect_statistics
    SAVE_TESTINPUTS = args.save_inputs
    SAVE_TESTCASES = args.save_tests

    if RAN_SEED is not None:
        random.seed(RAN_SEED)

    if args.verbose:
        LOGGER.setLevel(logging.DEBUG)

    is_c = args.file[-2:] == '.c'
    is_i = args.file[-2:] == '.i'
    is_source = is_c or is_i

    if is_source:
        source = args.file
        stem = source[:-2]

        if args.m32 and args.m64:
            LOGGER.error("-32 is incompatible with -64")
            sys.exit(2)

        if args.m32:
            verifier_c = "__VERIFIER32.c"
        else:
            verifier_c = "__VERIFIER.c"

        if args.compile == "make":
            if args.o:
                LOGGER.warning("--compile make overrides -o INSTR_BIN")
            INSTR_BIN = stem + ".instr"
            LOGGER.info('Making {}'.format(INSTR_BIN))
            sp.run(["make", "-B", INSTR_BIN, "MAX_TRACE_LEN={}".format(TREE_DEPTH_LIMIT)])
        elif args.compile == "svcomp":
            if not args.o:
                LOGGER.error("--compile svcomp requires -o INSTR_BIN")
                sys.exit(2)
            INSTR_BIN = args.o
            asm = INSTR_BIN + ".s"
            ins = INSTR_BIN + ".instr.s"
            sp.run([args.cc, "-no-pie", "-o", asm, "-S", source])
            sp.run(["./tracejump.py", asm, ins])
            sp.run([args.cc, "-no-pie", "-O0", "-o", INSTR_BIN, verifier_c,
                    "__VERIFIER_assume.instr.s",
                    "__trace_jump.s",
                    "__trace_buffered.c",
                    ins,
                    "-DMAX_TRACE_LEN={}".format(TREE_DEPTH_LIMIT)])
        elif args.compile == "trace-cc":
            if args.o:
                INSTR_BIN = args.o
            else:
                INSTR_BIN = stem
            LOGGER.info('Compiling {} with trace-cc'.format(INSTR_BIN))
            sp.run(["./trace-cc", "-static", "-L.", "-legion", "-o", INSTR_BIN, source])
        else:
            LOGGER.error("Invalid compilation mode: {}".format(args.compile))
            sys.exit(2)

        sp.run(["file", INSTR_BIN])

        UNINSTR_BIN = ".".join(INSTR_BIN.split(".")[:-1])
        sp.run(["file", INSTR_BIN])
        sp.run([args.cc, "-no-pie", "-O0", "-o", UNINSTR_BIN,
                verifier_c, "__VERIFIER_assume.c", source])
    else:
        INSTR_BIN = args.file

    binary_name = INSTR_BIN.split("/")[-1]
    DIR_NAME = "{}_{}_{}_{}".format(binary_name, MIN_SAMPLES, TIME_COEFF, TIME_START)
    PROGRAM_NAME = args.file.split("/")[-1]
    if is_source and SAVE_TESTCASES:
        os.system("mkdir -p tests/{}".format(DIR_NAME))
        with open("tests/{}/metadata.xml".format(DIR_NAME), "wt+") as md:
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

    try:
        if args.verbose:
            cProfile.run('main()', sort='cumtime')
        else:
            print(main())
    finally:
        pass
