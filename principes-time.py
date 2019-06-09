import gc
import logging
import os
import pdb
import random
import re
import struct
import subprocess
import sys
import time
from multiprocessing import Pool
from math import sqrt, log, ceil

import angr

# from memory_profiler import profile
# from Results.pie_maker import make_pie
# from binary_execution import binary_execute


MAX_PATHS = float('inf')
MAX_ROUNDS = float('inf')
MIN_SAMPLES = int(sys.argv[1])

DSC_PATHS = set()
PST_INSTRS = set()
CUR_ROUND = 0
TTL_SEL = 0

SIMUL_COUNT = 0
TIME_COEFF = int(sys.argv[2])

RHO = sqrt(2)

QS_COUNT = 0
RD_COUNT = 0
BINARY_EXECUTION_COUNT = 0
SYMBOLIC_EXECUTION_COUNT = 0

FOUND_BUG = False

TIME_START = time.time()
TIME_LOG = {}
MEMO_LOG = []
MEMO_DIF = []
PID = None
ROOT = None
PHANTOM = None
REAL_PHAN = None
PHANTOM_STATES = {}

BINARY = sys.argv[2]
PRE_SEEDS = sys.argv[3:]
SEEDS = []
for seed in PRE_SEEDS:
    SEEDS.append(seed)
    SEEDS.append('\n')
SEEDS = [SEEDS]

PROJ = None

LOGGER = logging.getLogger("Principes")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)

# BLACKLIST = "../Benchmarks/sv-benchmarks/BlacklistBenchmarks"
BLACKLIST = "./BlacklistBenchmarks"


def timer(method):
    global TIME_LOG

    def timeit(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if method.__name__ in TIME_LOG:
            TIME_LOG[method.__name__] += te - ts
        else:
            TIME_LOG[method.__name__] = te - ts
        return result

    return timeit


def my_profile():
    global MEMO_LOG
    mem = os.popen("more /proc/{}/statm".format(PID)).read().split(" ")
    MEMO_LOG.append([mem[0], mem[1]])


def generate_random():
    random_bytes = b''
    # for _ in SEEDS[0]:
    # Assume 100 bytes input should be long enough for all binaries
    for _ in range(100):
        random_bytes += os.urandom(1)
    return random_bytes


class TreeNode:
    """
    NOTE:
        Node colour:
            White:  In TraceJump     + Not sure if in Angr   + check Symbolic state later    + may have simulation child
            Red:    In TraceJump     + Confirmed in Angr     + has Symbolic state            + has Simulation child
            Black:  In TraceJump     + Confirmed not in Angr + No Symbolic state             + No Simulation child
            Gold:   Not in TraceJump + Not in Angr           + Same Symbolic state as parent + is a Simulation child
            Purple: Unknown TJ path  + SymEx found in Angr   + has Symbolic state            + is a Phantom Node
    """

    def __init__(self, addr, parent=None, state=None, colour='W', phantom=False, samples=None):
        self.exhausted = False
        self.addr = addr
        self.parent = parent
        self.state = state
        self.samples = samples
        self.colour = colour
        self.phantom = phantom
        self.fully_explored = False

        self.children = {}  # {addr: Node}
        self.sel_try = 0
        self.sel_win = 0
        self.sim_try = 0
        self.sim_win = 0
        self.distinct = 0
        self.visited = 0
        self.accumulated_time = 0
        self.count = 0
        # self.average_time = 0

    def __del__(self):
        del self.visited
        del self.distinct
        del self.sim_try
        del self.sim_win
        del self.sel_try
        del self.sel_win
        del self.children
        del self.fully_explored
        del self.phantom
        del self.colour
        del self.samples
        del self.state
        del self.parent
        del self.addr
        del self.exhausted
        del self

    def best_child(self):

        max_score = -float('inf')
        candidates = []
        for child in self.children.values():
            # child = child.next_non_black_child()
            child_score = uct(child)
            LOGGER.info("\033[0mCandidate: {}\033[0m".format(child))
            if child_score == max_score:
                candidates.append(child)
            if child_score > max_score:
                max_score = child_score
                candidates = [child]

        return random.choice(candidates)

    # @timer
    def next_non_black_child(self):
        if self.colour is not 'B':
            return self
        if not self.children:
            return self
        if len(self.children) == 1:
            return self.children[
                list(self.children.keys())[0]].next_non_black_child()
        return self.best_child()

    # @timer
    def dye(self, colour, state=None, samples=None):
        assert self.colour is 'W'
        assert (colour is 'B' and not state) or (colour is 'R' and state)

        self.colour = colour
        if colour is 'R':
            self.children['Simulation'] \
                = TreeNode(addr=self.addr, parent=self, state=state, colour='G', samples=samples)
        LOGGER.info("Dye {}".format(self))

    def is_diverging(self):
        # Return if self is a diverging node in the current incomplete tree
        return (len(self.children) - ('Simulation' in self.children)) > 1

    def mark_exhausted(self):
        assert not self.exhausted
        self.exhausted = True
        if self.colour is 'R':
            self.children['Simulation'].exhausted = True
            del self.children['Simulation'].samples
            gc.collect()
        else:
            assert self.colour is 'G'
            self.parent.exhausted = True
            del self.samples
            gc.collect()

    def is_exhausted(self):
        return self.exhausted or \
               ('Simulation' in self.children
                and self.children['Simulation'].exhausted)

    # @timer
    def mutate(self):
        if self.state.solver.constraints and not self.exhausted:
            return self.quick_sampler()
        return self.random_sampler()

    @timer
    def quick_sampler(self):
        global QS_COUNT
        self.count += 1
        LOGGER.info("Using quick sampler")
        LOGGER.debug("{}'s constraint: {}"
                     .format(hex(self.addr), self.state.solver.constraints))
        target = self.state.posix.stdin.load(0, self.state.posix.stdin.size)

        assert not self.exhausted

        if self.colour == 'P' and self.samples:
            pdb.set_trace()
            self.samples = None

        if not self.samples:
            assert not self.sel_try
            self.samples = self.state.solver.iterate(e=target)

        results = []
        n = (target.size() + 7) // 8  # Round up to the next full byte
        while len(results) < 100:
            try:
                val = next(self.samples)
                if (val is None) and len(results) > MIN_SAMPLES:
                    break
                if val is None:
                    continue
                result = val.to_bytes(n, 'big')
                results.append(result)
            except StopIteration:
                # NOTE: Meaning the path is not feasible?
                # if self.colour == 'P' and not len(results):
                #     pdb.set_trace()
                self.exhausted = True
                self.samples = None
                gc.collect()
                break
        QS_COUNT += len(results)
        return results

    # @timer
    @staticmethod
    def random_sampler():
        global RD_COUNT
        RD_COUNT += MIN_SAMPLES
        return [generate_random() for _ in range(MIN_SAMPLES)]

    def add_child(self, addr, passed_parent=False):
        global PHANTOM, REAL_PHAN
        is_new_child = addr not in self.children.keys()
        if is_new_child:
            self.children[addr] = TreeNode(addr=addr, parent=self)
        if not PHANTOM or addr != PHANTOM.addr or not passed_parent:
            return is_new_child
        # pdb.set_trace()
        if self.children[addr].colour != 'W':
            # NOTE: Somehow the real node of the phantom is dyed
            if not self.children[addr].colour == 'R':
                if self.children[addr].colour == 'B':
                    self.children[addr].colour = 'W'
                else:
                    pdb.set_trace()
            else:
                PHANTOM = None
                return is_new_child
            # Note: if it is red

            # # assert self.children[addr].state == PHANTOM.state
            # if self.children[addr].samples != PHANTOM.samples:
            #     LOGGER.debug("PHANTOM path: ", [hex(addr) for addr in PHANTOM.print_path()])
            #     LOGGER.debug("CURRENT path: ", [hex(addr) for addr in self.print_path()])
            #     LOGGER.debug("NEXT    addr: ", hex(addr))
            #     # pdb.set_trace()
            # return is_new_child
        self.children[addr].dye(colour='R', state=PHANTOM.state, samples=PHANTOM.samples)
        # self.children[addr].children['Simulation'].average_time = PHANTOM.average_time

        self.children[addr].count = 1
        self.children[addr].accumulated_time = PHANTOM.accumulated_time
        self.children[addr].children['Simulation'].count = 1
        self.children[addr].children['Simulation'].accumulated_time = PHANTOM.accumulated_time
        REAL_PHAN = self.children[addr]

        # self.children[addr].children['Simulation'].sim_try = PHANTOM.sel_try
        # self.children[addr].children['Simulation'].sim_try = PHANTOM.sel_win
        # self.children[addr].children['Simulation'].sim_try = PHANTOM.sim_try
        # self.children[addr].children['Simulation'].sim_try = PHANTOM.sim_win
        parent = self
        # pdb.set_trace()
        while parent.colour == 'W':
            parent.dye('B')
            parent = parent.parent

        parent = self
        keep_state = False
        # NOTE: Need to keep the closest state if at least
        #  one child does not have a symbolic state
        #  Otherwise, there will be no point to start future symbolic steps
        while parent:
            keep_state = keep_state or not parent.all_children_have_state()
            # if keep_state or \
            #         any([child.colour in ['P', 'W']
            #              for child in parent.children.values()]):
            if keep_state:
                keep_state = 'Simulation' not in parent.children
                parent = parent.parent
                continue
            parent.remove_redundant_state()
            parent = parent.parent
            # keep_state = parent.all_children_have_state()
        if self.children[addr].colour is 'R':
            PHANTOM = None
            REAL_PHAN = self.children[addr]
        if PHANTOM:
            pdb.set_trace()
        return is_new_child

    def all_children_have_state(self):
        # NOTE: starting from the current node, check if all children subtrees
        #   have a symbolic state to execute from.
        children = list(self.children.values())
        # pdb.set_trace()
        while children:
            child = children.pop()
            if child.colour in ['W', 'P']:
                return False
            if 'Simulation' in child.children:
                assert child.children['Simulation'].state
                continue
            # NOTE: Red OR Black
            children.extend(child.children.values())
        return True

    def mark_fully_explored(self):
        self.fully_explored = True
        self.remove_redundant_state()
        LOGGER.info("Mark {} as FULLY EXPLORED".format(self))

    def remove_redundant_state(self):
        if any([child.colour == 'W'
                for child in self.children.values()]):
            return
        if 'Simulation' not in self.children.keys():
            return
        # if 'Simulation' in self.children \
        #         and all([child.colour not in ['P', 'W'] for child in self.children.values()]):
        LOGGER.info("Remove Simulation Node {}".format(
            self.children['Simulation']))

        # del self.children['Simulation']
        self.children['Simulation'].fully_explored = True

        # gbc = gc.collect()
        # LOGGER.debug(
        #     "\033[1;32mGarbage collector: collected {} objects\033[0m"
        #     .format(gbc))

    def print_path(self):
        path, parent = [self.addr], self.parent
        while parent:
            path.append(parent.addr)
            parent = parent.parent
        return path[::-1]

    # @timer
    def pp(self, indent=0, mark_node=None, found=0, forced=False):
        if LOGGER.level > logging.INFO and not forced:
            return
        s = ""
        for _ in range(indent - 1):
            s += "|   "
        if indent > 15 and self.parent and self.parent.colour is 'W':
            print("...")
            return
        if indent:
            s += "|-- "
        s += str(self)
        if self == mark_node:
            s += "\033[1;32m <=< found {}\033[0;m".format(found)
        print(s)
        if self.children:
            indent += 1

        for _, child in sorted(list(self.children.items()),
                               key=lambda k: str(k)):
            child.pp(indent=indent, mark_node=mark_node,
                     found=found, forced=forced)

    def repr_node_name(self):
        return ("Simul Node: " if self.colour is 'G' else
                "Phant Node: " if self.colour is 'P' else
                "@Root Node: " if self.colour is 'R' and not self.parent else
                "Block Node: ") \
               + (hex(self.addr)[-4:] if self.addr else "None")

    def repr_node_data(self):
        return "{uct:.2f}: {simw:}/{simt} + {r:.2f}*sqrt({t_sel:.2f}/{sel_t}), " \
               "({sel_w}) - {time:.4f} / 2^(log_2({samples}) + {count}) "\
            .format(uct=uct(self), simw=self.sim_win, simt=self.sim_try+1,
                    r=RHO, t_sel=log(TTL_SEL+1), sel_t=self.sel_try,
                    sel_w=self.sel_win,
                    time=self.accumulated_time, samples=MIN_SAMPLES,
                    count=self.count)

    def repr_node_state(self):
        return "State: {}".format(self.state if self.state else "None")

    def repr_node_child(self):
        return ["{}: {})".format(child.repr_node_name(), child.repr_node_data())
                for _, child in self.children.items()]

    def __repr__(self):
        # return '\033[1;{colour}m{name}: {state}, {con}\033[0m'\
        #     .format(colour=30 if self.colour is 'B' else
        #             31 if self.colour is 'R' else
        #             33 if self.colour is 'G' else
        #             37 if self.colour is 'W' else
        #             35 if self.colour is 'P' else 32,
        #             name=self.repr_node_name(),
        #             state=self.repr_node_state(),
        #             con=self.state.solver.constraints if self.state
        #             else "as above" if self.colour == 'B'
        #             else 'Omitted' if 'Simulation' not in self.children
        #             else self.children['Simulation'].state.solver.constraints)
        return '\033[1;{colour}m{name}: {state}, {data}, {phantom}\033[0m'\
            .format(colour=30 if self.colour is 'B' else
                    31 if self.colour is 'R' else
                    33 if self.colour is 'G' else
                    37 if self.colour is 'W' else
                    35 if self.colour is 'P' else 32,
                    name=self.repr_node_name(),
                    state=self.repr_node_state(),
                    data=self.repr_node_data(),
                    children=self.repr_node_child(),
                    phantom=self.phantom)


# @timer
def uct(node):
    if node.fully_explored:
        return -float('inf')
    if not node.sel_try:
        return float('inf')
    exploit = node.sim_win / (node.sim_try + 1)
    explore = sqrt(log(TTL_SEL + 1) / node.sel_try)

    # Note: Only the first time to solve a node takes
    #   ceil(log_2(MIN_SAMPLES) + 1)
    #   number of constraint solving
    #   The rest only needs 1
    #   So if a node has not been selected before,
    #   its estimated time penalisation is
    #   that number * its parent's average constraint solving time
    #   If that node has been selected before,
    #   its estimated time penalisation is
    #   1 * its own average constraint solving time

    # Note: Similarly, given a node that has been counted N times (N>0),
    #  the estimated number of constraint solving it conducted is
    #  ceil(log_2(MIN_SAMPLES) + 1) + (N-1)
    #  hence average constraint solving time is:
    #  accumulated_time / (ceil(log_2(MIN_SAMPLES)) + N)

    if node.count or not node.parent:
        time_penalisation \
            = node.accumulated_time / ceil(log(MIN_SAMPLES, 2) + node.count)
    else:
        time_penalisation \
            = node.parent.accumulated_time / ceil(log(MIN_SAMPLES, 2))

    return exploit + RHO * explore - time_penalisation * TIME_COEFF


@timer
def run():
    global CUR_ROUND, ROOT, PROJ
    history = []
    ROOT = initialisation()
    del PROJ
    CUR_ROUND += 1
    ROOT.pp()
    while keep_fuzzing(ROOT):
        history.append([CUR_ROUND, ROOT.distinct])
        mcts(ROOT)
        CUR_ROUND += 1
    # ROOT.pp(forced=True)
    return history


@timer
def initialisation():
    initialise_angr()
    return initialise_seeds(
        TreeNode(addr=None, parent=None, state=None, colour='W'))


# @timer
def initialise_angr():
    global PROJ
    PROJ = angr.Project(BINARY)


# @timer
def initialise_seeds(root):
    # NOTE: prepare the root (dye red, add simulation child)
    #  otherwise the data in simulation stage of SEEDs
    #   cannot be recorded without building another special case
    #   recorded in the simulation child of it.
    #   Cannot dye root with dye_to_the_next_red() as usual, as:
    #       1. The addr of root will not be known before simulation
    #       2. The function requires a red node
    #       in the previous line of the node to dye,
    #       which does not exist for root
    root.dye(colour='R', state=PROJ.factory.entry_state(
        stdin=angr.storage.file.SimFileStream))
    seed_paths = simulation_stage(node=root.children['Simulation'],
                                  input_str=SEEDS)
    are_new = expansion_stage(root, seed_paths)
    propagation_stage(root, seed_paths, are_new,
                      [root, root.children['Simulation']])
    # Make sure all paths are starting from the same addr
    assert len(set([path[0] for path in seed_paths])) == 1
    while root.children['Simulation'].state.addr != root.addr:
        succs = execute_symbolically(state=root.children['Simulation'].state)
        assert len(succs) == 1  # Make sure no divergence before root
        root.children['Simulation'].state = succs[0]
    return root


def keep_fuzzing(root):
    LOGGER.error(
        msg="\033[1;35m== Iter:{} == Time:{} == Path:{}"
                 "== SAMPLE_COUNT:{} == QS: {} == RD: {} ==\033[0m"
                 .format(CUR_ROUND, int(time.time()-TIME_START), root.distinct,
                         BINARY_EXECUTION_COUNT, QS_COUNT, RD_COUNT)
    )
    # We probably should remove this restriction, consider the following two paths:
    # path1 = [1,2,3], path2 = [1,2,3,4]
    # There are two distinct paths in DSC_PATHS but the same for legion (and software testing).
    # if not root.distinct == len(DSC_PATHS):
        # for path in DSC_PATHS:
        #     print([hex(addr) for addr in path])
    #    pdb.set_trace()
    return len(DSC_PATHS) < MAX_PATHS \
        and CUR_ROUND < MAX_ROUNDS \
        and not FOUND_BUG \
        and not ROOT.fully_explored


def mcts(root):
    global PHANTOM, REAL_PHAN
    nodes = selection_stage(root)
    while not nodes:
        nodes = selection_stage(root)
    PHANTOM = nodes[-1] if nodes[-1].colour is 'P' else None
    if PHANTOM:
        if PHANTOM.samples is not None:
            pdb.set_trace()
    paths = simulation_stage(nodes[-1])
    # NOTE: What if len(paths) < NUM_SAMPLES?
    #  i.e. fuzzer finds less mutant than asked
    #  Without handling this, we will be trapped in the infeasible node,
    #  whose num_visited is always 0
    #  I saved all nodes along the path of selection stage and used them here
    if PHANTOM:
        nodes[-1].parent.children.pop(nodes[-1].addr)
        nodes.pop()
        gc.collect()
    are_new = expansion_stage(root, paths)
    if REAL_PHAN:
        nodes.extend([REAL_PHAN, REAL_PHAN.children['Simulation']])
        REAL_PHAN = None
    propagation_stage(
        root, paths, are_new, nodes, 0,
        PHANTOM is not None)
    # root.pp(indent=0, mark_node=nodes[-1], found=sum(are_new), forced=not math.fmod(CUR_ROUND, 50))


# @timer
def selection_stage(node):
    global MEMO_LOG

    nodes, prev_red_index = tree_policy(node=node)
    if nodes[-1].state:
        return nodes

    assert nodes[-1].addr and not nodes[-1].children  # is a leaf
    return tree_policy_for_leaf(nodes=nodes, red_index=prev_red_index)


# @timer
def tree_policy(node):
    nodes, prev_red_index = [], 0

    while node.children:
        if ROOT.fully_explored:
            exit(3)
        LOGGER.info("\033[1;32mSelect\033[0m: {}".format(node))
        # if not (not node.parent or node.parent.colour is 'R'
        #     or node.parent.colour is 'B'):
        #     pdb.set_trace()
        if node.colour is 'W':
            dye_to_the_next_red(start_node=node, last_red=nodes[prev_red_index])
        if 'Simulation' in node.children:
            prev_red_index = len(nodes)
        # NOTE: No need to distinguish red or black here
        nodes.append(node)
        node = node.best_child()
    nodes.append(node)
    LOGGER.info("Final: {}".format(nodes[-1]))
    return nodes, prev_red_index


# @timer
def dye_to_the_next_red(start_node, last_red):
    if 'Simulation' not in last_red.children:
        pdb.set_trace()
    last_state = last_red.children['Simulation'].state
    succs = compute_line_children_states(state=last_state)
    while not dye_red_black_node(candidate_node=start_node,
                                 target_states=succs,
                                 phantom_parent=last_red) \
            and not start_node.is_diverging() \
            and start_node.children:
        start_node = next(v for v in start_node.children.values())


# @timer
def compute_line_children_states(state):
    """
    Symbolically execute to the end of the line of the state
    :param state: the state which is in the line to execute through
    :return: a list of the immediate children states of the line,
        could be empty if the line is a leaf
    """
    children = execute_symbolically(state=state)
    ls = []
    while children is not None and len(children) == 1:
        ls.append(children[0])
        children = execute_symbolically(state=children[0])
    return children


# @timer
def dye_red_black_node(candidate_node, target_states, phantom_parent):
    global PHANTOM_STATES
    for state in target_states:
        if candidate_node.addr == state.addr and not candidate_node.phantom:
            candidate_node.dye(colour='R', state=state)
            target_states.remove(state)

            if state in PHANTOM_STATES:
                LOGGER.debug("Phantom Node {} turns out to be {}".format(
                    PHANTOM_STATES[state], candidate_node))
                del PHANTOM_STATES[state].parent.children[
                    PHANTOM_STATES[state].addr]
                del PHANTOM_STATES[state]
            break
    if candidate_node.colour is 'R':
        for state in target_states:
            if state.addr in phantom_parent.children:
                continue
            phantom_parent.children[state.addr] = TreeNode(
                addr=state.addr, parent=phantom_parent, state=state, colour='P')
            PHANTOM_STATES[state] = phantom_parent.children[state.addr]
        return True
    candidate_node.dye(colour='B')
    return False


@timer
def execute_symbolically(state):
    succ = []
    try:
        global SYMBOLIC_EXECUTION_COUNT
        SYMBOLIC_EXECUTION_COUNT += 1
        LOGGER.debug("Step: {}".format(hex(state.addr)))
        succ = state.step().successors
    except:
        pass
        # pdb.set_trace()
    return succ


# @timer
def tree_policy_for_leaf(nodes, red_index):
    # NOTE: Roll back to the immediate red ancestor
    #  and only keep the path from root the that ancestor's simulation child
    LOGGER.info(
        "Select: {} as {} is a leaf".format(nodes[red_index], nodes[-1]))
    # TODO: mark the closest red parent as fully explored

    closest_branching_target = nodes[-1]
    while all([child.fully_explored for name, child
               in closest_branching_target.children.items()
               if (name is not 'Simulation')]):
        closest_branching_target.mark_fully_explored()
        if not closest_branching_target.parent:
            exit(3)
        closest_branching_target = closest_branching_target.parent

    all_explored = False
    while closest_branching_target and 'Simulation' not in closest_branching_target.children:
        all_explored = all([child.fully_explored for child in closest_branching_target.children.values()])
        closest_branching_target = closest_branching_target.parent
    if closest_branching_target and all_explored:
        closest_branching_target.remove_redundant_state()
    return []


# @timer
def simulation_stage(node, input_str=None):
    if PHANTOM and node.samples:
        # NOTE: This should never happen, otherwise it is likely to trigger
        #   the problem (that should never happen) below
        pdb.set_trace()

    start_solving = time.time()
    mutants = [bytes("".join(mutant), 'utf-8')
               for mutant in input_str] if input_str else node.mutate()
    end_solving = time.time()

    paths = [program(mutant) for mutant in mutants]
    # paths = pool.map(program, mutants)
    # print(len(node.state.solver.constraints), time.time() - start_solving)
    node.accumulated_time += (end_solving - start_solving)
    # Note; if not paths then the node's quick sampler is exhausted.
    #  It will only be fuzzed with the random sampler.

    return paths


@timer
def binary_execute(input_str):
    sp = subprocess.Popen(
        BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    try:
        msg = sp.communicate(input_str, timeout=30*60*60)
        returncode = sp.returncode
        sp.kill()
        del sp
        # gc.collect()
        return msg, returncode
    except subprocess.TimeoutExpired:
        with open(BLACKLIST, 'a') as blacklist:
            blacklist.writelines(['\n'+BINARY[:-4]])
        exit(2)


# @timer
def program(input_str):
    global BINARY_EXECUTION_COUNT, FOUND_BUG, MEMO_DIF
    BINARY_EXECUTION_COUNT += 1

    def unpack(output):
        assert (len(output) % 8 == 0)
        # NOTE: changed addr[0] to addr
        return [addr for i in range(int(len(output) / 8))
                for addr in struct.unpack_from('q', output, i * 8)]

    save_input_to_file(input_str)
    report = binary_execute(input_str)
    if report:
        msg, return_code = report
        error_msg = msg[1]
        FOUND_BUG = return_code == 100
        if FOUND_BUG:
            print("\n*******************"
                  "\n***** EUREKA! *****"
                  "\n*******************\n")
        # LOGGER.info("\033[1;32mGarbage collector: collected {} objects\033[0m"
        #             .format(gc.collect()))
        return unpack(error_msg)
    pdb.set_trace()
    return [ROOT.addr]


@timer
def expansion_stage(root, paths):
    are_new = []
    for path in paths:
        if tuple(path) in DSC_PATHS:
            are_new.append(expand_path(root, path))
            if are_new[-1]:
                pdb.set_trace()
        else:
            are_new.append(expand_path(root, path))
    return are_new


# @timer
def expand_path(root, path):
    global DSC_PATHS, PHANTOM
    DSC_PATHS.add(tuple(path))
    LOGGER.info("INPUT_PATH: {}".format([hex(addr) for addr in path]))

    # Either Root before SEED or it must have an addr
    assert (not root.addr or root.addr == path[0])

    if not root.addr:  # NOTE: assign addr to root
        root.addr = path[0]
        root.children['Simulation'].addr = root.addr
    node, is_new, passed_parent = root, False, False
    # if PHANTOM and PHANTOM.addr not in path:
    #     pdb.set_trace()
    #     PHANTOM.parent.children[PHANTOM.addr] = PHANTOM
    #     PHANTOM = None
    for addr in path[1:]:
        if PHANTOM and node == PHANTOM.parent:
            passed_parent = True or passed_parent
        # have to put node.child(addr) first to avoid short circuit
        is_new = node.add_child(addr, passed_parent) or is_new
        node = node.children[addr]
    if PHANTOM is not None:
        # NOTE: This should not happen as the first input from QuickSampler
        #   should guarantee to preserve the path
        #   This is just a temp solution
        pdb.set_trace()
        # PHANTOM.samples = None
        # new_path = program(PHANTOM.quick_sampler()[0])
        # results = expand_path(root, new_path)
        # pdb.set_trace()
        # return results
        # PHANTOM.parent.children[PHANTOM.addr] = PHANTOM
        # PHANTOM = None
    return is_new


# @timer
def propagation_stage(root, paths, are_new, nodes, short=0, is_phantom=False):
    assert len(paths) == len(are_new)
    root.pp(indent=0, mark_node=nodes[-1], found=sum(are_new))
    for i in range(len(paths)):
        # NOTE: If the simulation is on a phantom node,
        #   reset every node along the path as not fully explored
        #   as the real node may be deeper than phantom
        #   only do this for the first path,
        #   as it is the only path that guarantees to preserve the real path
        neo_propagate_path(
            root, paths[i], are_new[i], nodes, is_phantom and not i)

    # NOTE: If number of inputs generated by fuzzer < NUM_SAMPLES,
    #  then we need to update the node in :param nodes
    #  (whose addr might be different from :param paths)
    #  otherwise we might be trapped in some nodes
    for node in nodes:
        node.visited += short

    for i in range(len(paths)):
        propagate_path(root, paths[i], are_new[i], nodes[-1])

    for node in nodes[::-1]:
        if node.is_diverging():
            break
        node.accumulated_time = nodes[-1].accumulated_time
        node.count = nodes[-1].count
    # root.pp(indent=0, mark_node=nodes[-1], found=sum(are_new))


def propagate_path(root, path, is_new, node):
    if node is not root:
        node.visited += 1
        node.distinct += is_new
    node = root
    assert node.addr == path[0]
    for addr in path[1:]:
        node.visited += 1
        node.distinct += is_new
        # assert node.distinct <= MAX_PATHS
        if addr not in node.children:
            pdb.set_trace()
        node = node.children.get(addr)
        assert node
    node.visited += 1
    node.distinct += is_new


# @timer
def neo_propagate_path(root, path, is_new, nodes, is_phantom):
    global TTL_SEL
    preserved = True
    for i in range(len(nodes)-1):
        preserved = preserved and len(path) > i and path[i] == nodes[i].addr
        nodes[i].sel_win += preserved
        nodes[i].sel_try += 1
        TTL_SEL += 1
    nodes[-1].sel_win += preserved
    nodes[-1].sel_try += 1
    TTL_SEL += 1

    node = root
    node.sim_win += is_new
    node.sim_try += 1
    for addr in path[1:]:
        if not node.children.get(addr):
            pdb.set_trace()
        node = node.children.get(addr)
        node.sim_win += is_new
        node.sim_try += 1
        node.fully_explored = node.fully_explored and not is_phantom

    nodes[-1].sim_win += is_new
    nodes[-1].sim_try += preserved


def make_constraint_readable(constraint):
    con_str = "["
    for con in constraint:
        con_ops = re.search(pattern='<Bool (.*?) [<=>]*? (.*)>',
                            string=str(con))
        op_str1 = "INPUT_STR" if 'stdin' in con_ops[1] \
            else str(int(con_ops[1], 16) if '0x' in con_ops[1] else con_ops[1])
        op_str2 = "INPUT_STR" if 'stdin' in con_ops[2] \
            else str(int(con_ops[2], 16) if '0x' in con_ops[2] else con_ops[2])
        con_str += con_ops[0].replace(con_ops[1], op_str1) \
            .replace(con_ops[2], op_str2)
        con_str += ", "

    return con_str + "]"


def save_input_to_file(input_bytes):
    binary_name = BINARY.split("/")[-1][:-6]
    if "{}_{}".format(binary_name , MIN_SAMPLES) not in os.listdir('inputs'):
        os.system("mkdir inputs/{}_{}".format(binary_name, MIN_SAMPLES))
    time_stamp = time.time()-TIME_START
    with open('inputs/{}_{}/{}'.format(binary_name, MIN_SAMPLES, time_stamp), 'wb') as input_file:
        input_file.write(input_bytes)

# def save_input_to_file(input_bytes):
#     binary_name = BINARY.split("/")[-1][:-6]
#     if "{}_{}".format(binary_name, TIME_START) not in os.listdir('inputs'):
#         os.system("mkdir inputs/{}_{}".format(binary_name, TIME_START))
#     time_stamp = time.time()-TIME_START
#     with open('inputs/{}_{}/{}'.format(binary_name, TIME_START, time_stamp),
#               'wb') as input_file:
#         input_file.write(input_bytes)

# def display_results():
#     for i in range(len(categories)):
#         print("{:25s}: {:-9.6f} / {:-3d} = {:3.6f}"
#               .format(categories[i], values[i], units[i], averages[i]))


if __name__ == "__main__" and len(sys.argv) > 1:
    assert BINARY and SEEDS
    pool = Pool(MIN_SAMPLES)

    LOGGER.info(BINARY)
    LOGGER.info(SEEDS)
    PID = os.getpid()
    # state = PROJ.factory.entry_state()
    # pdb.set_trace()
    run()

    print(MEMO_LOG)
    print(MEMO_DIF)
    # pdb.set_trace()
    # ITER_COUNT = run()[-1][0]
    for method_name, method_time in TIME_LOG.items():
        print("{:28s}: {}".format(method_name, method_time))

    assert CUR_ROUND
    categories = ['Iteration Number',
                  'Samples Number / iter',
                  'Total time',
                  'Symbolic Execution',
                  'Binary Execution',
                  'Path Preserve Fuzzing',
                  # 'Random Fuzzing',
                  # 'Tree Expansion'
                  ]

    values = [CUR_ROUND,
              MIN_SAMPLES,
              TIME_LOG['run'],  # Time
              # Symbolic execution
              TIME_LOG['initialisation'] + TIME_LOG['execute_symbolically'],
              TIME_LOG['binary_execute'],  # Binary execution
              TIME_LOG['quick_sampler'],  # Quick sampler
              # TIME_LOG['random_sampler'],  # Random sampler
              # TIME_LOG['expansion_stage']  # Expansion
              ]

    units = [1,
             1,
             QS_COUNT + RD_COUNT,  # Time
             # ITER_COUNT * NUM_SAMPLES,  # Time
             SYMBOLIC_EXECUTION_COUNT,  # Binary execution
             # ITER_COUNT * NUM_SAMPLES,  # Initialisation
             BINARY_EXECUTION_COUNT,  # Binary execution
             # SYMBOLIC_EXECUTION_COUNT,  # Symbolic execution
             QS_COUNT,  # Quick sampler
             # RD_COUNT,  # Random sampler
             # MAX_PATHS  # Expansion time
             ]

    averages = [values[i] / units[i] for i in range(len(values))]

    if not len(categories) == len(values) == len(units) == len(averages):
        pdb.set_trace()

    # if len(DSC_PATHS) != MAX_PATHS:
    #     pdb.set_trace()
    for i in range(len(categories)):
        print(categories[i], values[i], units[i])
    # print(values, units)
    # display_results()
    # make_pie(categories=categories, values=values,
    #          units=units, averages=averages)
