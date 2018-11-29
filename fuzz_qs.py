import sys
import traceback
import random
import angr
import tracer
import claripy
import time
from math import sqrt, log
from Results.pie_maker import make_pie

import subprocess32
import struct

C = 1/sqrt(2)

samples = 1
max_rounds = 100

total = 30
max_iterations = 1000
MAX_PATH = 9

ALL_MUTATION = 0
WRG_MUTATION = 0


PREV_CONSTRANTS = []

ANGR_TIME = 0.
TRACER_TIME = 0.
FUZZER_TIME = 0.
SIMLTR_TIME = 0.
SIMLTR_COUNT = 0.
RAN_FUZZER_TIME = 0.
TREE_POLICY_TIME = 0.
EXPANSION_TIME = 0.
CONSTRAINT_PARSING_TIME = 0.

FUZZER_COUNT = 0
RAN_FUZZER_COUNT = 0

SIMGR = None
ALL_PATHS = set()


def cannot_terminate(path_count):
    return len(ALL_PATHS) < MAX_PATH


class Node:
    def __init__(self, path, state=None, constraint=None, dummy=False):
        assert path

        self.path = path
        self.children = {}  # {addr: Node(tuple(path up to addr))}
        self.distinct = 0
        self.visited = 0
        # each element is a set of constraints along one path to the node
        self.constraints = []
        if constraint:
            self.constraints = [constraint]

        self.state = state
        # print("init:{}".format(self.constraints))
        if not dummy:
            self.children['Simulation'] = Node(
                path, constraint=constraint, dummy=True)

    def add_constraint(self, constraint):

        if constraint:
            # TODO: find a better way to compare constraints
            self.constraints.append(constraint)
            self.children['Simulation'].constraints.append(constraint)
            return

        self.constraints = []
        self.children['Simulation'].constraints = []

    def get_constraint(self):
        # print("Get Constraint from {}".format(self.constraints))
        # TODO: return the hardest constraint
        if self.constraints:
            # assert (
            #     self.children['Simulation'].constraints == self.constraints)
            # print(random.choice(self.constraints))
            return random.choice(self.constraints)
        # assert(not self.children['Simulation'].constraints)
        return None

    def is_path_node(self):
        return 'Simulation' in self.children

    # def insert(self, path, test_run=False):
    #     """
    #     path represents the full path from root to leaf
    #     """
    #     self.visited += 1 if not test_run else 0
    #     starts_new_path = False
    #
    #     if not path:
    #         return starts_new_path
    #
    #     child_addr = path[0]
    #
    #     if child_addr not in self.children.keys():  # new child
    #         self.children[child_addr] = Node(self.path + (child_addr,))
    #         # self.children['Simulation'].distinct += 1
    #         starts_new_path = True
    #
    #     starts_new_path = self.children[child_addr].insert(
    #         path[1:]) or starts_new_path
    #     self.distinct += starts_new_path if not test_run else 0
    #     self.children['Simulation'].distinct \
    #         += starts_new_path if not test_run else 0
    #     return starts_new_path

    def insert_descendants(self, simgr, path, parent_constraint=None):
        """
        path represents the full path from root to leaf
        """
        global TRACER_TIME, CONSTRAINT_PARSING_TIME
        # print("\n")

        # if self.path[-1] is None:
        #     self.path = path[:1]
        # if len(self.path) == 1:
        #     self.path = (self.path, simgr.active[0].addr)
        # print("simgr.active:{}".format(simgr.active))
        # print("path[-1]: {}".format(self.path[-1]))

        # while simgr.active[0].addr != path[0]:
        #     simgr.step()
            # print ("simgr.active:{} => path[0]:{}".format(
            #     simgr.active, hex(path[0])))

        # print(map(hex, [simgr.active[0].addr, path[0], self.path[-1]]))
        # assert([simgr.active[0].addr == path[0] == self.path[-1]])

        # # state = simgr.active[0]
        # assert((self.path[0] == simgr.active[0].addr))

        # if remained:
        #     print("Remained: {}".format(self.path[-1]))
        self.visited += 1

        starts_new_path = False
        start = time.time()
        psimgr = simgr.copy()
        i = 0
        curr_cons = len(simgr.active[0].solver.constraints)

        while simgr.active and len(path) > i \
                and (curr_cons == len(simgr.active[0].solver.constraints)):

            # print("Before Explore", simgr.active, path)
            simgr.explore(find=lambda s: print_addr(s, path[i]))
            # print("pre ", simgr.found, simgr.active)
            simgr.move('found', 'active')
            # print(simgr.active)
            i += 1
            # print("post", simgr.found, simgr.active)
            # print("simgr.active:{}".format(simgr.active))
            # print(self.constraints)
            # print(curr_cons, len(simgr.active[0].solver.constraints), curr_cons == len(simgr.active[0].solver.constraints))

        if not simgr.active or not path:
            end = time.time()
            TRACER_TIME += end - start
            if path:
                print("Warning!! Path : {} is not empty while Active is: {}"
                      .format(path, simgr.active))
            if simgr.active:
                print("Warning!! Active : {} is not empty while Path is: {}"
                      .format(simgr.active, path))
            return starts_new_path

        # start = time.time()
        # remained = simgr.active[0].addr != self.path[-1]
        # end = time.time()
        # TRACER_TIME += end - start



        child = simgr.active[0]

        end = time.time()
        TRACER_TIME += end - start

        child_addr = child.addr

        if child_addr not in self.children.keys():  # new child
            start = time.time()

            preconstraints = set(simgr.active[0].preconstrainer.preconstraints)
            all_constraint = set(simgr.active[0].solver.constraints)
            child_constraint = list(all_constraint-preconstraints)
            # print("preconstraints", preconstraints)
            # print(all_constraint)
            # print(child_constraint)
            end = time.time()
            CONSTRAINT_PARSING_TIME += end - start
            if child_constraint and child_constraint != parent_constraint:
                # print("child constraint: {}".format(child_constraint))
                self.children[child_addr] = Node(
                    self.path + (child_addr,), simgr.active[0], child_constraint)
                self.children[child_addr].state = simgr.active[0]
                # self.children['Simulation'].distinct += 1
                starts_new_path = True
                # if not BRANCHING_POINT:
                #     BRANCHING_POINT = self.path[-1]

        # print(self.info())
        # if child_addr in self.children.keys():
        starts_new_path = \
            self.children[child_addr].insert_descendants(simgr, path[i:], self.constraints) \
            or starts_new_path
        # else:
        #     starts_new_path = \
        #         self.insert_descendants(simgr, path[1:], self.constraints) or starts_new_path

        # print("#### {} ####".format(starts_new_path))
        self.distinct += starts_new_path
        self.children['Simulation'].distinct += starts_new_path
        # print(self.info())
        return starts_new_path

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
            # NodePath=[hex(addr) if addr else 'Root' for addr in self.path],
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


def print_addr(state, addr):
    # print(hex(state.addr))
    return state.addr == addr


def generate_random(seed):
    bytes = [random.randint(0, 255)
             for _ in seed]  # WTF Python: range is inclusive
    input = "".join(map(chr, bytes))
    return input


def initialise_simgr(binary, seed, path):

    global SIMGR
    global ANGR_TIME

    start = time.time()
    p = angr.Project(binary)
    entry = p.factory.entry_state(addr=path[0], stdin=angr.storage.file.SimFileStream)
    entry.preconstrainer.preconstrain_file(seed, entry.posix.stdin, True)
    simgr = p.factory.simulation_manager(entry, save_unsat=False)

    # SIMGR = simgr.copy()
    # end = time.time()
    # ANGR_TIME += (end - start)
    return simgr


def mutate(node, program, seed, samples):
    global FUZZER_TIME, FUZZER_COUNT, RAN_FUZZER_TIME, RAN_FUZZER_COUNT, SIMLTR_TIME, SIMLTR_COUNT
    start = time.time()

    if node.constraints:
        constraint = node.get_constraint()
        # print(constraint)
        solver = claripy.Solver()
        for con in constraint:
            # print(con)
            solver.add(con)
        vals = solver.eval(constraint[0].args[0].args[1], samples)
        results = [chr(val) for val in vals]
        end = time.time()
        FUZZER_TIME += (end-start)
        FUZZER_COUNT += 1
    else:
        results = [generate_random(seed) for _ in range(samples)]
        end = time.time()
        RAN_FUZZER_TIME += (end-start)
        RAN_FUZZER_COUNT += 1

    return results


def uct(node):
    if node.is_path_node():
        return uct(node.children['Simulation'])

    global total
    assert(total > 0)
    assert(node.visited >= 0)
    if not node.visited:
        return float('inf')
    exploit = (node.distinct / node.visited)
    explore = (sqrt(log(total) / node.visited))
    # return exploit + C * explore
    # print(node.info())

    return exploit + C * explore


def playout_full(node, program, seed):
    global SIMLTR_TIME, SIMLTR_COUNT
    results = mutate(node, program, seed, samples)

    start = time.time()
    paths = [program(result) for result in results]
    end = time.time()
    SIMLTR_TIME += (end-start)
    SIMLTR_COUNT += samples
    if len(results) != len(paths):
        print("Error! len(results) != len(paths)")
    return [[results[i], paths[i]] for i in range(len(results))]
    # return [path for path in paths if path]  # paths starts from node.child


def traced(binary):  # curry the input argument + convert result to immutable tuple

    def with_input(input):
        return tuple(traced_with_input(binary, input))

    return with_input


def unpack(output):
    assert(len(output) % 8 == 0)
    addrs = []
    for i in xrange(len(output) / 8):
        addr = struct.unpack_from('q', output, i * 8)  # returns a tuple
        addrs.append(addr[0])
    return addrs


def traced_with_input(binary, input):
    p = subprocess32.Popen(binary, stdin=subprocess32.PIPE, stderr=subprocess32.PIPE)
    (output, error) = p.communicate(input)
    addrs = unpack(error)

    # Abandon QEMU Runner
    # runner = tracer.qemu_runner.QEMURunner(binary, input)
    # addrs = runner.trace
    return addrs


def run(binary, seed):
    # try:
    global max_iterations, ALL_PATHS, FUZZER_COUNT

    global SIMGR
    iter_count = 1
    history = []

    program = traced(binary)
    root = Node((None,))

    # while max_iterations:
    #     mcts(root, program, seed)
    #     max_iterations -= 1
    path = program(seed)
    # i=1
    # print([hex(addr) for addr in path])
    # print([hex(addr) for addr in path])
    ALL_PATHS.add(path)
    # print(ALL_PATHS)
    simgr = initialise_simgr(binary, seed, path)

    # simgr = SIMGR.copy()
    # addrs_tracer = angr.exploration_techniques.Tracer(trace=path)
    # simgr.use_technique(addrs_tracer)
    root.path = (simgr.active[0].addr,)
    root.state = simgr.active[0]
    root.insert_descendants(simgr, path[1:])

    # for addr in path:
    #     simgr.explore(find=lambda s: print_addr(s, addr))
    #     print("pre ", simgr.found, simgr.active)
    #     simgr.move('found', 'active')
    #     for fin in simgr.active:
    #         print(fin.solver.constraints)
    #     print("post", simgr.found, simgr.active)

    # while not BRANCHING_POINT and i<=len(path):

    #     i += 1
    # node = [child for name, child in node.children.items() if name != 'Simulation'][0]
    # path = path[:1]
    #
    # print(BRANCHING_POINT, )
    # assert(BRANCHING_POINT)
    # print(root.distinct)
    # pre = 0
    while cannot_terminate(root.distinct):
        print("======== {}:{}:{}:{} ========".format(
            iter_count, root.distinct, len(ALL_PATHS), FUZZER_COUNT))
        # root.pp()
        history.append([iter_count, root.distinct])
        mcts(root, program, seed)
        iter_count += 1
        # if root.distinct != pre:
        #     print("{},{}".format(iter_count, root.distinct))
        #     # print("======== {}:{} ========".format(iter_count, root.distinct))
        #     pre == root.distinct
        # if iter_count >= max_iterations:
        # 	break
    # except:
    #     traceback.print_exc(file=sys.stdout)

    return history
    # root.pp()
    # print(iter_count)
# def mcts_rec(node, program, seed):
#     # child = None if the node is a 'Simulation' node, which has no children.
#     child = max(node.children.values(), key=uct) if node.children else None
#     # Recursion always stops at a simulation node,
#     # no matter its parent is an intermediate node, or a leaf node
#     num_win, num_sim = mcts(child) if child else simulate(node, program, seed)

#     node.distinct += num_win
#     node.visited += num_sim

#     return num_sim, num_win


def mcts(root, program, seed):
    global TREE_POLICY_TIME, EXPANSION_TIME, TRACER_TIME, ALL_PATHS

    prev_node = None
    node = root

    # while node.path[-1] != BRANCHING_POINT:
    #     node = [child for child in node.children.values() if child.is_path_node()][0]

    # while node.path[-1] != BRANCHING_POINT:
    #     node = best_child(node)
    start = time.time()

    while node.children:
        # print(node.path[-1], BRANCHING_POINT)
        # if node.path[-1] != BRANCHING_POINT:
        #     continue
        # print(node.info())
        prev_node = node
        node = best_child(node)  # will always be a sim_node

    end = time.time()
    TREE_POLICY_TIME += (end - start)
    # print('Tree policy gives node = {}'.format(node.info()))
    results = playout_full(node, program, seed)  # Full path
    num_win, num_sim = 0, len(results)

    start = time.time()
    for result in results:
        node.visited += num_sim
        mutated_input, path = result
        if path in ALL_PATHS:
            continue
        # ALL_PATHS.add(path)
        # print(ALL_PATHS)
        simgr_start = time.time()
        simgr = initialise_simgr(binary, mutated_input, path)
        # addrs_tracer = angr.exploration_techniques.Tracer(trace=path)
        # simgr.use_technique(addrs_tracer)
        # tmp = simgr.run(until=lambda tmp_simgr: prev_node.state.addr == tmp_simgr.active[0].addr)
        simgr_end = time.time()
        TRACER_TIME += (simgr_end-simgr_start)

        new_win = root.insert_descendants(simgr, path[1:]) if path else 0
        if new_win:
            node.distinct += new_win
            # for old_path in ALL_PATHS:
                # print([hex(i) for i in old_path])
            # print([hex(i) for i in path])
            if path in ALL_PATHS:
                print("Error, not new")
            ALL_PATHS.add(path)


    end = time.time()
    EXPANSION_TIME += (end - start)
    # if new_win:

    # TODO: prettier print
    # print("New path = {}".format([hex(p_node)[-4:] for p_node in path]))
    # num_win += new_win

    # print(node.info())


def best_child(node):
    # if not node.is_path_node():
    #     return node

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


def simulate(node, program, seed):
    suffixes = playout_full(node, program, seed)  # suffix starts from node.child

    num_win = sum([node.parent.insert(suffix) for suffix in suffixes])
    num_sim = len(suffixes)

    return num_win, num_sim


if __name__ == "__main__" and len(sys.argv) > 1:
    start = time.time()

    global binary, seed
    binary = sys.argv[1]
    args = sys.argv[2:]
    seed = ''.join(args)
    # print('seed')
    # print(seed)
    iter_count = run(binary, seed)[-1][0]
    end = time.time()
    assert(len(ALL_PATHS) == MAX_PATH)

    assert(iter_count)
    print("Iter_count = {}".format(iter_count))
    print("TOTAL_TIME = {}".format(end-start))
    print("AVG_TTL_TIME = {}".format((end-start)/iter_count))
    print("ANGR_TIME = {}".format(ANGR_TIME))
    print("AVG_ANGR_TIME = {}".format(ANGR_TIME/iter_count))
    print("TRACER_TIME = {}".format(TRACER_TIME))
    print("AVG_TRACER_TIME = {}".format(TRACER_TIME/iter_count))
    print("SIMLTR_TIME = {}".format(SIMLTR_TIME))
    print("AVG_SIMLTR_TIME = {}".format(SIMLTR_TIME/iter_count))
    print("QS_FZ_TIME = {}".format(FUZZER_TIME))
    print("AVG_QS_TIME = {}".format(FUZZER_TIME/FUZZER_COUNT))
    print("RAN_FZ_TIME = {}".format(RAN_FUZZER_TIME))
    print("AVG_RN_TIME = {}".format(RAN_FUZZER_TIME/RAN_FUZZER_COUNT))
    print("TREE_POLICY_TIME = {}".format(TREE_POLICY_TIME))
    print("AVG_TREE_POLICY_TIME = {}".format(TREE_POLICY_TIME/iter_count))
    print("CONSTRAINT_PARSING_TIME = {}".format(CONSTRAINT_PARSING_TIME))
    print("AVG_CONSTRAINT_PARSING_TIME = {}".format(
        (CONSTRAINT_PARSING_TIME)/MAX_PATH))
    print("EXPANSION_TIME = {}".format(
        EXPANSION_TIME - TRACER_TIME - CONSTRAINT_PARSING_TIME))
    print("AVG_EXPANSION_TIME = {}".format(
        (EXPANSION_TIME - TRACER_TIME - CONSTRAINT_PARSING_TIME)/MAX_PATH))

    make_pie(
        categories=['Iteration', 'Total', 'Angr', 'QEMU',
                    'Tracer', 'ConstraintParsing", QuickSampler', 'RandomFuzzing',
                    'TreePolicy', 'TreeExpansion'],
        values=[iter_count, end-start, ANGR_TIME, SIMLTR_TIME,
                TRACER_TIME, CONSTRAINT_PARSING_TIME. FUZZER_TIME, RAN_FUZZER_TIME,
                TREE_POLICY_TIME, EXPANSION_TIME - TRACER_TIME],
        averages=['/', (end-start)/iter_count, ANGR_TIME/iter_count, SIMLTR_TIME/iter_count,
                  TRACER_TIME/iter_count, (CONSTRAINT_PARSING_TIME)/MAX_PATH, FUZZER_TIME /
                  FUZZER_COUNT, RAN_FUZZER_TIME/RAN_FUZZER_COUNT,
                  TREE_POLICY_TIME/iter_count, (EXPANSION_TIME - TRACER_TIME)/iter_count]
    )
