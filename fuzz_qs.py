import logging
import pdb
import random
import struct
import subprocess
import sys
import time
from math import sqrt, log

import angr
import claripy

from Results.pie_maker import make_pie

MAX_PATHS = 9
NUM_SAMPLES = 1
DSC_PATHS = set()
# TODO: Track past inputs as well as discovered path
MAX_ROUNDS = float('inf')
CUR_ROUND = 0

RHO = 1 / sqrt(2)

QS_TIME = 0.
RD_TIME = 0.
QS_COUNT = 0
RD_COUNT = 0
ANGR_TIME = 0.
TRACER_TIME = 0.
SIMLTR_TIME = 0.
SIMLTR_COUNT = 0.
TREE_POLICY_TIME = 0.
EXPANSION_TIME = 0.
CONSTRAINT_PARSING_TIME = 0.

BINARY = sys.argv[1]
SEED = ''.join(sys.argv[2:])
ENTRY = None
PROJ = None
SYMBOLS = None

LOGGER = logging.getLogger("lg")
LOGGER.setLevel(logging.ERROR)


class Node:
    def __init__(self, path, constraint=None, dummy=False):
        assert path

        self.path = path
        self.children = {}  # {addr: Node}
        self.distinct = 0
        self.visited = 0
        # each element of constraints is a list of constraints along one path to the node
        self.constraints = [constraint] if constraint else []
        self.solver = None
        self.symbols = ''
        if not dummy:
            self.children['Simulation'] = Node(path, constraint=constraint, dummy=True)

    def get_constraint(self):
        # TODO: return the simplest constraint
        assert not self.is_path_node()
        if self.constraints:
            return random.choice(self.constraints)
        return None

    def is_path_node(self):
        return 'Simulation' in self.children

    def insert_descendants(self, simgr, path, parent_constraint=None):
        """
        path represents the full path from root to leaf
        """
        global TRACER_TIME, CONSTRAINT_PARSING_TIME, EXPANSION_TIME

        self.visited += 1
        starts_new_path = False

        tracer_start = time.time()
        curr_cons = len(simgr.active[0].solver.constraints)
        pos = 0
        while pos < len(path) and simgr.active \
                and curr_cons == len(simgr.active[0].solver.constraints):
            preconstraints = set(simgr.active[0].preconstrainer.preconstraints)
            all_constraint = set(simgr.active[0].solver.constraints)
            child_constraint = list(all_constraint - preconstraints)
            pc = (hex(simgr.active[0].addr), child_constraint)

            simgr.explore(find=lambda s: compare_addr(s, path[pos]))
            simgr.move('found', 'active')

            preconstraints = set(simgr.active[0].preconstrainer.preconstraints)
            all_constraint = set(simgr.active[0].solver.constraints)
            child_constraint = list(all_constraint - preconstraints)
            cc = (hex(simgr.active[0].addr), child_constraint)

            pos += 1

        if not simgr.active or not path:
            tracer_end = time.time()
            TRACER_TIME += tracer_end - tracer_start

            if path:
                LOGGER.debug("Path : {} is not empty while Active is: {}"
                             .format(path, simgr.active))
            if simgr.active:
                LOGGER.debug("Active : {} is not empty while Path is: {}"
                             .format(simgr.active, path))
            return starts_new_path

        child = simgr.active[0]
        tracer_end = time.time()
        TRACER_TIME += tracer_end - tracer_start

        child_addr = child.addr

        if child_addr not in self.children.keys():  # new child
            constraint_parsing_start = time.time()

            preconstraints = set(simgr.active[0].preconstrainer.preconstraints)
            all_constraint = set(simgr.active[0].solver.constraints)
            child_constraint = list(all_constraint-preconstraints)

            constraint_parsing_end = time.time()
            CONSTRAINT_PARSING_TIME += constraint_parsing_end - constraint_parsing_start

            expansion_start = time.time()
            if child_constraint and child_constraint != parent_constraint:
                self.children[child_addr] = Node(self.path + (child_addr,), child_constraint)
                self.children[child_addr].children['Simulation'].solver = claripy.Solver()
                self.children[child_addr].children['Simulation'].solver.add(child_constraint)
                for con in child_constraint:
                    for c in con.args:
                        if type(c.args[1]) is claripy.ast.BV:
                            self.children[child_addr].children['Simulation'].symbols \
                                = c.args[1].concat(self.symbols)
                assert self.children[child_addr].children['Simulation'].symbols is not ''
                starts_new_path = True
            expansion_end = time.time()
            EXPANSION_TIME += expansion_end - expansion_start

        starts_new_path = self.children[child_addr].insert_descendants(
            simgr, path[pos:], self.constraints) or starts_new_path

        self.distinct += starts_new_path
        self.children['Simulation'].distinct += starts_new_path
        return starts_new_path

    def solve_in_str(self):
        return self.solver.eval(self.symbols, NUM_SAMPLES)

    def info(self):
        node_score = "{0:4s}: {1:.4f}({2:1d}/{2:1d})".format(
            (hex(self.path[-1])[-4:] if self.path[-1]
             else 'Root') + ("" if self.is_path_node() else "Sim"),
            uct(self),
            self.distinct,
            self.visited)
        children_score = ["{0:4s}: {1:.4f}({2:1d}/{2:1d})".format(
            (hex(child.path[-1])[-4:] if child.path[-1]
             else 'Root') + ("" if child.is_path_node() else "Sim"),
            uct(child),
            child.distinct,
            child.visited)
            for name, child in self.children.items()]
        return '{NodeType}: {NodePath}, {constraint}, C:{children}'.format(
            NodeType='PathNode' if self.is_path_node() else 'SimulationChild',
            NodePath=node_score,
            constraint=self.constraints,
            children=children_score)

    def pp(self, indent=0):
        i = "  " * indent
        s = i
        s += 'Path node: ' if self.is_path_node() else 'Simulation Child: '
        s += hex(self.path[-1]) if self.path[-1] else 'Root'
        s += " "
        s += "(" + str(self.distinct) + "/" + str(self.visited) + ")"
        s += " "
        s += "score = " + str(uct(self))
        s += " "
        print(s)
        if self.children:
            indent += 1
        for addr, child in self.children.items():
            child.pp(indent)


def compare_addr(state, addr):
    return state.addr == addr


def cannot_terminate(root):
    LOGGER.info("=== Iter:{} === Root.distinct:{} === len(DSC_PATHS):{} === QS_COUNT:{} ==="
                .format(CUR_ROUND, root.distinct, len(DSC_PATHS), QS_COUNT))
    return len(DSC_PATHS) < MAX_PATHS and CUR_ROUND < MAX_ROUNDS


def generate_random():
    in_str = "".join(map(chr, [random.randint(0, 255) for _ in SEED]))
    return in_str


def initialise_angr(path):
    global ANGR_TIME, ENTRY, PROJ
    # TODO: Change to only call once
    angr_start = time.time()
    PROJ = angr.Project(BINARY)
    ENTRY = PROJ.factory.entry_state(addr=path[0], stdin=angr.storage.file.SimFileStream)
    angr_end = time.time()
    ANGR_TIME += angr_end - angr_start


def initialise_simgr(in_str):
    global TRACER_TIME

    entry = ENTRY.copy()

    tracer_start = time.time()
    entry.preconstrainer.preconstrain_file(in_str, entry.posix.stdin, True)
    simgr = PROJ.factory.simulation_manager(entry, save_unsat=False)
    tracer_end = time.time()
    TRACER_TIME += tracer_end - tracer_start

    return simgr


def mutate(node):
    global QS_TIME, QS_COUNT, RD_TIME, RD_COUNT

    mutate_start = time.time()

    if node.solver:
        vals = node.solve_in_str()
        results = [chr(val) for val in vals]
        mutate_end = time.time()
        QS_TIME += mutate_end - mutate_start
        QS_COUNT += NUM_SAMPLES
        return results

    assert not any(node.constraints)

    results = [generate_random() for _ in range(NUM_SAMPLES)]
    mutate_end = time.time()
    RD_TIME += mutate_end - mutate_start
    RD_COUNT += NUM_SAMPLES

    return results


def uct(node):
    if node.is_path_node():
        return uct(node.children['Simulation'])

    if not node.visited:
        return float('inf')

    exploit = node.distinct / node.visited
    explore = sqrt(log(CUR_ROUND) / node.visited)

    return exploit + RHO * explore


def playout_full(node):
    global SIMLTR_TIME, SIMLTR_COUNT

    results = mutate(node)

    simul_start = time.time()
    paths = [program(result) for result in results]
    simul_end = time.time()
    SIMLTR_TIME += simul_end - simul_start
    SIMLTR_COUNT += NUM_SAMPLES

    assert len(results) == len(paths) == NUM_SAMPLES

    return [[results[i], paths[i]] for i in range(len(results))]


def program(in_str):
    return tuple(traced_with_input(in_str))


def unpack(output):
    assert(len(output) % 8 == 0)

    addrs = []
    for i in xrange(len(output) / 8):
        addr = struct.unpack_from('q', output, i * 8)  # returns a tuple
        addrs.append(addr[0])
    return addrs


def traced_with_input(in_str):
    p = subprocess.Popen(BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    if type(in_str) is not bytes:
        pdb.set_trace()
    (output, error) = p.communicate(in_str)
    addrs = unpack(error)

    # runner = tracer.qemu_runner.QEMURunner(BINARY, in_str)
    # addrs = runner.trace

    return addrs


def run():
    global CUR_ROUND, DSC_PATHS
    history = []

    raw_path = program(SEED)
    initialise_angr(raw_path)
    DSC_PATHS.add(raw_path)

    simgr = initialise_simgr(SEED)
    root = Node((simgr.active[0].addr,))

    path = []
    for i, addr in enumerate(raw_path):
        if i < 3 or addr != 4197276:
            path.append(addr)
        else:
            path.append(4197295)
    # path = [addr for addr in raw_path if (addr != 4197276 or raw_path.index(addr) < 3)]
    # while simgr.active:
    #     print(hex(simgr.active[0].addr), simgr.active[0].solver.constraints)
    #     simgr.step()

    root.insert_descendants(simgr, path[1:])
    CUR_ROUND += 1

    while cannot_terminate(root):
        assert root.distinct == len(DSC_PATHS)
        history.append([CUR_ROUND, root.distinct])
        mcts(root)
        CUR_ROUND += 1

    return history


def mcts(root):
    global TREE_POLICY_TIME, TRACER_TIME, DSC_PATHS

    node = root

    tree_policy_start = time.time()

    while node.children:
        node = best_child(node)

    tree_policy_end = time.time()
    TREE_POLICY_TIME += tree_policy_end - tree_policy_start

    results = playout_full(node)
    num_win, num_sim = 0, len(results)

    for result in results:
        node.visited += num_sim

        mutated_in_str, path = result
        if path in DSC_PATHS:
            continue
        DSC_PATHS.add(path)
        simgr = initialise_simgr(mutated_in_str)
        new_win = root.insert_descendants(simgr, path[1:])
        assert new_win


def best_child(node):

    max_score = -float('inf')
    candidates = []
    for child in node.children.values():
        child_score = uct(child)
        if child_score == max_score:
            candidates.append(child)
        if child_score > max_score:
            max_score = child_score
            candidates = [child]

    return random.choice(candidates)


# def best_child(node):
#     uct_tie = []
#     max_score = None
#     for child in node.children.values():
#         if not max_score:
#             max_score = uct(child)
#             uct_tie.append(child)
#             continue
#
#         cur_score = uct(child)
#         if max_score == cur_score:
#             uct_tie.append(child)
#             continue
#
#         if cur_score > max_score:
#             max_score = cur_score
#             uct_tie = [child]
#
#     assert(uct_tie)
#
#     if len(uct_tie) == 1:
#         return uct_tie.pop()
#
#
#     win_tie = []
#     max_win= None
#     for child in uct_tie:
#         if not max_win:
#             max_win = child.distinct
#             win_tie.append(child)
#             continue
#         if max_win == child.distinct:
#             win_tie.append(child)
#             continue
#         if child.distinct > max_win:
#             win_tie = [child]
#
#     assert(win_tie)
#     if len(win_tie) == 1:
#         return win_tie.pop()
#
#     assert(win_tie)
#     vis_tie = []
#     min_vis = None
#     for child in win_tie:
#         if not min_vis:
#             min_vis = child.visited
#             vis_tie.append(child)
#             continue
#         if min_vis == child.visited:
#             vis_tie.append(child)
#             continue
#         if child.visited < vis_tie:
#             vis_tie = [child]
#
#
#     assert(vis_tie)
#     if len(vis_tie) == 1:
#         return vis_tie.pop()
#
#     for child in vis_tie:
#         if not child.is_path_node():
#             return child
#     return vis_tie.pop()


def simulate(node):
    suffixes = playout_full(node)  # suffix starts from node.child

    num_win = sum([node.parent.insert(suffix) for suffix in suffixes])
    num_sim = len(suffixes)

    return num_win, num_sim


if __name__ == "__main__" and len(sys.argv) > 1:
    assert BINARY and SEED
    start = time.time()
    iter_count = run()[-1][0]
    end = time.time()

    assert (len(DSC_PATHS) == MAX_PATHS)
    assert iter_count
    LOGGER.info("Iter_count = {}".format(iter_count))
    LOGGER.info("TOTAL_TIME = {}".format(end-start))
    LOGGER.info("AVG_TTL_TIME = {}".format((end-start)/iter_count))
    LOGGER.info("ANGR_TIME = {}".format(ANGR_TIME))
    LOGGER.info("AVG_ANGR_TIME = {}".format(ANGR_TIME/iter_count))
    LOGGER.info("TRACER_TIME = {}".format(TRACER_TIME))
    LOGGER.info("AVG_TRACER_TIME = {}".format(TRACER_TIME/iter_count))
    LOGGER.info("SIMLTR_TIME = {}".format(SIMLTR_TIME))
    LOGGER.info("AVG_SIMLTR_TIME = {}".format(SIMLTR_TIME/iter_count))
    LOGGER.info("QS_FZ_TIME = {}".format(QS_TIME))
    LOGGER.info("AVG_QS_TIME = {}".format(QS_TIME / QS_COUNT))
    LOGGER.info("RAN_FZ_TIME = {}".format(RD_TIME))
    LOGGER.info("AVG_RN_TIME = {}".format(RD_TIME / RD_COUNT))
    LOGGER.info("TREE_POLICY_TIME = {}".format(TREE_POLICY_TIME))
    LOGGER.info("AVG_TREE_POLICY_TIME = {}".format(TREE_POLICY_TIME/iter_count))
    LOGGER.info("CONSTRAINT_PARSING_TIME = {}".format(CONSTRAINT_PARSING_TIME))
    LOGGER.info("AVG_CONSTRAINT_PARSING_TIME = {}".format(CONSTRAINT_PARSING_TIME / MAX_PATHS))
    LOGGER.info("EXPANSION_TIME = {}".format(EXPANSION_TIME))
    LOGGER.info("AVG_EXPANSION_TIME = {}".format(EXPANSION_TIME / MAX_PATHS))

    make_pie(
        categories=['Iteration', 'Total', 'Angr', 'TraceJump',
                    'Tracer', 'ConstraintParsing', 'QuickSampler', 'RandomFuzzing',
                    'TreePolicy', 'TreeExpansion'],
        values=[iter_count, end - start, ANGR_TIME, SIMLTR_TIME,
                TRACER_TIME, CONSTRAINT_PARSING_TIME, QS_TIME, RD_TIME,
                TREE_POLICY_TIME, EXPANSION_TIME],
        averages=['/', (end-start) / iter_count, ANGR_TIME / iter_count, SIMLTR_TIME / iter_count,
                  TRACER_TIME / iter_count, CONSTRAINT_PARSING_TIME / MAX_PATHS,
                  QS_TIME / QS_COUNT, RD_TIME / RD_COUNT,
                  TREE_POLICY_TIME / iter_count, EXPANSION_TIME / iter_count]
    )
