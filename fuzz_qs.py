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
    return path_count < MAX_PATH


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

    def update(self, distinct, visited):
        self.distinct += distinct
        self.visited += visited

    def insert(self, path, test_run=False):
        """
        path represents the full path from root to leaf
        """
        self.visited += 1 if not test_run else 0
        starts_new_path = False

        if not path:
            return starts_new_path

        child_addr = path[0]

        if child_addr not in self.children.keys():  # new child
            self.children[child_addr] = Node(self.path + (child_addr,))
            # self.children['Simulation'].distinct += 1
            starts_new_path = True

        starts_new_path = self.children[child_addr].insert(
            path[1:]) or starts_new_path
        self.distinct += starts_new_path if not test_run else 0
        self.children['Simulation'].distinct \
            += starts_new_path if not test_run else 0
        return starts_new_path

    def insert_descendants(self, simgr, parent_constraint=None):
        """
        path represents the full path from root to leaf
        """
        global TRACER_TIME, CONSTRAINT_PARSING_TIME
        # print("\n")

        # if self.path[-1] is None:
        #     self.path = path[:1]
        if len(self.path) == 1:
            self.path = (self.path, simgr.active[0].addr)
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
        start = time.time()
        remained = simgr.active[0].addr != self.path[-1]
        end = time.time()
        TRACER_TIME += end - start

        # if remained:
        #     print("Remained: {}".format(self.path[-1]))

        self.visited += 0 if remained else 1

        starts_new_path = False

        curr_state = simgr.active[0]
        start = time.time()
        simgr.step()
        # print("simgr.active:{}".format(simgr.active))
        # print(self.constraints)
        if not simgr.active:
            end = time.time()
            TRACER_TIME += end - start
            # simgr.step()
            return starts_new_path

        child = simgr.active[0]

        end = time.time()
        TRACER_TIME += end - start

        child_addr = child.addr

        if child_addr not in self.children.keys():  # new child
            start = time.time()
            child_constraint = simgr.active[0].solver.constraints
            # child_state =
            end = time.time()
            CONSTRAINT_PARSING_TIME += end - start
            if child_constraint and child_constraint != parent_constraint:
                # print("child constraint: {}".format(child_constraint))
                self.children[child_addr] = Node(
                    self.path + (child_addr,), child_constraint)
                self.children[child_addr].state = simgr.active[0]
                # self.children['Simulation'].distinct += 1
                starts_new_path = True
                # if not BRANCHING_POINT:
                #     BRANCHING_POINT = self.path[-1]

        # print(self.info())
        if child_addr in self.children.keys():
            starts_new_path = self.children[child_addr].insert_descendants(
                simgr, self.constraints) or starts_new_path
        else:
            starts_new_path = self.insert_descendants(
                simgr, self.constraints) or starts_new_path
        self.distinct += 0 if remained else starts_new_path
        self.children['Simulation'].distinct += \
            0 if remained else starts_new_path
        return starts_new_path

    def insert_state_descendants(self, simgr, parent_constraint=None):
        """
        path represents the full path from root to leaf
        """
        global TRACER_TIME, CONSTRAINT_PARSING_TIME
        # print("\n")

        # if self.path[-1] is None:
        #     self.path = path[:1]
        if len(self.path) == 1:
            self.path = (self.path, simgr.active[0].addr)
        # print("simgr.active:{}".format(simgr.active))
        # print("path[-1]: {}".format(self.path[-1]))

        # while simgr.active[0].addr != path[0]:
        #     simgr.step()
        #     print("simgr.active:{} => path[0]:{}".format( \
        #       simgr.active, hex(path[0])))

        # print(map(hex, [simgr.active[0].addr, path[0], self.path[-1]]))
        # assert([simgr.active[0].addr == path[0] == self.path[-1]])

        # # state = simgr.active[0]
        # assert((self.path[0] == simgr.active[0].addr))
        start = time.time()
        remained = simgr.active[0].addr != self.path[-1]
        end = time.time()
        TRACER_TIME += end - start

        # if remained:
        #     print("Remained: {}".format(self.path[-1]))

        self.visited += 0 if remained else 1

        starts_new_path = False

        curr_state = simgr.active[0]
        start = time.time()
        simgr.step()
        # print("simgr.active:{}".format(simgr.active))
        # print(self.constraints)
        if not simgr.active:
            end = time.time()
            TRACER_TIME += end - start
            # simgr.step()
            return starts_new_path

        child = simgr.active[0]

        end = time.time()
        TRACER_TIME += end - start

        child_addr = child.addr

        if child_addr not in self.children.keys():  # new child
            start = time.time()
            child_constraint = simgr.active[0].solver.constraints
            # child_state =
            end = time.time()
            CONSTRAINT_PARSING_TIME += end - start
            if child_constraint and child_constraint != parent_constraint:
                # print("child constraint: {}".format(child_constraint))
                self.children[child_addr] = Node(
                    self.path + (child_addr,), child_constraint)
                self.children[child_addr].state = simgr.active[0]
                # self.children['Simulation'].distinct += 1
                starts_new_path = True
                # if not BRANCHING_POINT:
                #     BRANCHING_POINT = self.path[-1]

        # print(self.info())
        if child_addr in self.children.keys():
            starts_new_path = self.children[child_addr].insert_descendants(
                simgr, self.constraints) or starts_new_path
        else:
            starts_new_path = self.insert_descendants(
                simgr, self.constraints) or starts_new_path
        self.distinct += 0 if remained else starts_new_path
        self.children['Simulation'].distinct += 0 if remained else starts_new_path
        return starts_new_path

    # def insert_child(self, child_addr,state):
    #     """
    #     path represents the full path from root to leaf
    #     """

    #     assert(state.addr == child_addr)

    #     self.visited += 1
    #     starts_new_path = False

    #     if not child_addr:
    #         return starts_new_path

    #     if child_addr not in self.children.keys(): # new child
    #         self.children[child_addr] = Node(self.path + (child_addr,))
    #         # self.children['Simulation'].distinct += 1
    #         starts_new_path = True

    #     starts_new_path = self.children[child_addr].insert(path[1:]) or starts_new_path
    #     self.distinct += starts_new_path if not test_run else 0
    #     self.children['Simulation'].distinct += starts_new_path if not test_run else 0
    #     return starts_new_path

    def info(self):
        children_score = ["{0:4s}: {1:.4f}({2:1d}/{2:1d})".format(
            (hex(child.path[-1])[-4:] if child.path[-1]
             else 'Root') + ("" if child.is_path_node() else "Sim"),
            uct(child),
            child.distinct,
            child.visited)
            for name, child in self.children.items()]
        return '{NodeType}: {NodePath}, {constraint}, C:{children}'.format(
            NodeType='PathNode' if self.is_path_node() else 'SimulationChild',
            NodePath=hex(self.path[-1])[-4:] if self.path[-1] else 'Root',
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


def generate_random(seed):
    bytes = [random.randint(0, 255)
             for _ in seed]  # WTF Python: range is inclusive
    input = "".join(map(chr, bytes))
    return input


def initialise_simgr(binary, prefix):

    global SIMGR
    global ANGR_TIME
    # runner = tracer.qemu_runner.QEMURunner(binary, seed)
    # addrs = runner.trace
    # if BRANCHING_POINT:
    #     return
    # prefix = node.path[1:]
    # prefix
    # print(prefix)

    # Time Angr
    start = time.time()
    p = angr.Project(binary)
    entry = p.factory.full_init_state(stdin=angr.storage.file.SimFileStream)
    # ANGR = copy.deepcopy(p)
    # ENTRY = copy.deepcopy(p)
    # state = p.factory.entry_state()
    # try:
    # print(state, type(state))
    # print(addrs[0], type(addrs[0]))
    simgr = p.factory.simulation_manager(entry, save_unsat=True)
    SIMGR = simgr.copy()
    end = time.time()
    ANGR_TIME += (end - start)

    # # Time Tracer
    # start = time.time()
    # addrs_tracer = angr.exploration_techniques.Tracer(trace=prefix)
    # simgr.use_technique(addrs_tracer)
    # # simgr.explore(find=lambda s: s.addr == prefix[-1])
    # # simgr.run()
    # state = simgr.active[0] if simgr.active else None
    # # print(state.addr != prefix[-1], state)
    # while state.addr != prefix[-1] and state:
    #     print("state", state)
    #     print("simgr", simgr.active)
    #     simgr.step()
    #     print(state, simgr.active)
    #     if not simgr.active or state == simgr.active[0]:
    #         break
    #     constraints = simgr.active[0].solver.constraints
    #     # print("final", final.addr, constraints)
    #     if constraints and not BRANCHING_POINT:
    #         # SIMGR = copy.deepcopy(simgr)
    #         BRANCHING_POINT = state.addr
    #         print("#### #### BRANCHING_POINT: {} #### ####".format(hex(BRANCHING_POINT)))
    #         # break
    #     state = simgr.active[0]
    # end = time.time()
    # TRACER_TIME += (end - start)
    # # SIMGR = copy.deepcopy(prev_simgr)
    # print("End", simgr.active)
    # #final = simgr.traced[0]
    # #print("simgr.traced", [i for i in simgr.traced])


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

    start = time.time()
    paths = [program(result) for result in results]
    end = time.time()
    SIMLTR_TIME += (end-start)
    SIMLTR_COUNT += samples

    return paths


# def mutate(prefix, program, seed, samples):
#     global max_rounds, ALL_MUTATION, WRG_MUTATION, PREV_CONSTRANTS, SIMGR
#     global ANGR_TIME, TRACER_TIME, FUZZER_TIME, FUZZER_COUNT, RAN_FUZZER_TIME, RAN_FUZZER_COUNT, SIMLTR_TIME
#     # results = []
#     rounds = 0
#     constraints = None
#     filtered_paths = []
#     print([hex(addr) for addr in prefix])
#     # branching_prefix = prefix[16:]
#     # print([hex(addr) for addr in branching_prefix if addr])
#     # addrs = [hex(addr) for addr in prefix]
#     # print("prefix: {}".format([addr[-3:] for addr in addrs]))
#     # print([addr[-3:] for addr in addrs])

#     if prefix:
#         # runner = tracer.qemu_runner.QEMURunner(binary, seed)
#         # addrs = runner.trace

#         # start = time.time()
#         # p = angr.Project(binary)
#         # entry = p.factory.full_init_state(stdin=angr.storage.file.SimFileStream)
#         # # state = p.factory.entry_state()
#         # # try:
#         # # print(state, type(state))
#         # # print(addrs[0], type(addrs[0]))
#         # p = copy.deepcopy(ANGR)
#         # simgr = p.factory.simulation_manager(entry, save_unsat=True)

#         # end = time.time()
#         # ANGR_TIME += (end - start)
#         simgr = SIMGR.copy()
#         print("mutate", simgr.active, SIMGR.active)
#         start = time.time()
#         addrs_tracer = angr.exploration_techniques.Tracer(trace=prefix)
#         simgr.use_technique(addrs_tracer)
#         # simgr.explore(find=lambda s: s.addr == prefix[-1])
#         # simgr.run()
#         print(simgr.active)
#         state = simgr.active[0] if simgr.active else None
#         while state.addr != prefix[-1] and state:
#             # print("state", state)
#             # print("simgr", simgr.active)
#             #
#             simgr.step()
#             print("mutate", simgr.active)
#             if not simgr.active or state == simgr.active[0]:
#                 break
#             state = simgr.active[0]
#         if simgr.active:
#             final = simgr.active[0]
#             constraints = final.solver.constraints
#             end = time.time()
#             TRACER_TIME += (end - start)
#         else:
#             constraints = state.solver.constraints
#             end = time.time()
#             TRACER_TIME += (end - start)
#             return [None]*samples
#         #final = simgr.traced[0]
#         #print("simgr.traced", [i for i in simgr.traced])
#         assert((state.addr == BRANCHING_POINT) or constraints)
#         # node.constraints = constraints
#         # print('recovered constraints:{}'.format([(c, type(c)) for c in constraints]))
#         #
#         # constraints = collect_constraints(node, binary)
#         # node.constraints =
#         if constraints:
#             # print('recovered constraints:{}'.format(constraints))
#             PREV_CONSTRANTS = constraints

#             start = time.time()
#             solver = claripy.Solver()
#             for constraint in constraints:
#                 solver.add(constraint)
#             results = solver.eval(constraints[0].args[0].args[1], samples)
#             # print(results)
#             # for c in constraints:
#             #     print(' ' + str(c))
#         # except angr.AngrError as a:
#             # print(a.args)
#             n = len(prefix)
#             end = time.time()
#             FUZZER_TIME += (end - start)
#             FUZZER_COUNT += 1
#             for result in results:
#                 # print(chr(result))
#                 start = time.time()
#                 path = program(chr(result))
#                 end = time.time()
#                 SIMLTR_TIME += (end - start)
#                 # print("path  : {}".format([str(addr)[-3:] for addr in path]))
#                 ALL_MUTATION += 1
#                 if path[:n] != prefix:
#                     WRG_MUTATION += 1
#                 else:
#                     filtered_paths.append(path)
#             print(ALL_MUTATION, WRG_MUTATION)
#     # print('generating inputs for prefix ' + str(map(hex, prefix)))

#             return filtered_paths

#     assert((state.addr == BRANCHING_POINT) or constraints)
#     ran_path= []
#     while len(ran_path) < samples and rounds < max_rounds:
#         rounds += 1
#         start = time.time()
#         input = generate_random(seed)
#         end = time.time()
#         RAN_FUZZER_TIME += (end - start)
#         RAN_FUZZER_COUNT += 1

#         start = time.time()
#         path = program(input)
#         end = time.time()
#         SIMLTR_TIME += (end - start)

#         n = len(prefix)
#         # result.append(path)
#         if path[:n] == prefix:
#             # print('using input "' + input + '" with path ' + str(map(hex, path)))
#             ran_path.append(path)
#         else:
#             print("#### WRONG RAN_PATH ####")
#         #     pass
#           # print('discarding input with path ' + str(map(hex, path)))
#     return ran_path


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
    # prefix = node.path[1:]

    # # p = angr.Project(binary)
    # # entry = p.factory.full_init_state(stdin=angr.storage.file.SimFileStream)
    # # state = p.factory.entry_state()
    # # # try:
    # # # print(state, type(state))
    # # # print(addrs[0], type(addrs[0]))
    # # simgr = p.factory.simulation_manager(entry, save_unsat=True)
    # # addrs_tracer = angr.exploration_techniques.Tracer(trace=prefix)
    # # simgr.use_technique(addrs_tracer)
    # # # simgr.explore(find=lambda s: s.addr == prefix[-1])
    # # # simgr.run()
    # # state = simgr.active[0] if simgr.active else None
    # # while state.addr != prefix[-1] and state:
    # #     # print("state", state)
    # #     # print("simgr", simgr.active)
    # #     simgr.step()
    # #     if not simgr.active or state == simgr.active[0]:
    # #         break
    # #     state = simgr.active[0]

    # #     final = simgr.active[0]
    # # #final = simgr.traced[0]
    # # #print("simgr.traced", [i for i in simgr.traced])
    # # constraints = final.solver.constraints

    # paths = mutate(prefix, program, seed, samples)
    paths = mutate(node, program, seed, samples)

    return [path for path in paths if path]  # paths starts from node.child


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
    # print(input)
    # p = subprocess32.Popen(binary, stdin=subprocess32.PIPE, stderr=subprocess32.PIPE)
    # (output, error) = p.communicate(input)
    # addrs = unpack(error)
    runner = tracer.qemu_runner.QEMURunner(binary, input)
    addrs = runner.trace
    return addrs


def run(binary, seed):
    # try:
    global max_iterations, ALL_PATHS

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

    ALL_PATHS.add(path)
    # print(ALL_PATHS)
    initialise_simgr(binary, path)

    simgr = SIMGR.copy()
    addrs_tracer = angr.exploration_techniques.Tracer(trace=path)
    simgr.use_technique(addrs_tracer)

    root.state = simgr.active[0]
    root.insert_descendants(simgr)

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
        # root.pp()
        history.append([iter_count, root.distinct])
        mcts(root, program, seed)
        iter_count += 1
        # print("======== {}:{} ========".format(iter_count, root.distinct))
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
        print(node.info())
        prev_node = node
        node = best_child(node)  # will always be a sim_node

    end = time.time()
    TREE_POLICY_TIME += (end - start)
    # print('Tree policy gives node = {}'.format(node.info()))
    paths = playout_full(node, program, seed)  # Full path
    num_win, num_sim = 0, len(paths)

    start = time.time()
    for path in paths:
        if path in ALL_PATHS:
            continue
        # ALL_PATHS.add(path)
        # print(ALL_PATHS)
        simgr_start = time.time()
        simgr = SIMGR.copy()
        addrs_tracer = angr.exploration_techniques.Tracer(trace=path)
        simgr.use_technique(addrs_tracer)
        # tmp = simgr.run(until=lambda tmp_simgr: prev_node.state.addr == tmp_simgr.active[0].addr)
        simgr_end = time.time()
        TRACER_TIME += (simgr_end-simgr_start)

        new_win = root.insert_descendants(simgr) if path else 0
        if new_win:
            for old_path in ALL_PATHS:
                print([hex(i) for i in old_path])
            print([hex(i) for i in path])
            ALL_PATHS.add(path)

        node.visited += num_sim
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

#         cur_score = uct(child)
#         if max_score == cur_score:
#             uct_tie.append(child)
#             continue

#         if cur_score > max_score:
#             max_score = cur_score
#             uct_tie = [child]

#     assert(uct_tie)

#     if len(uct_tie) == 1:
#         return uct_tie.pop()


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

#     assert(win_tie)
#     if len(win_tie) == 1:
#         return win_tie.pop()

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


#     assert(vis_tie)
#     if len(vis_tie) == 1:
#         return vis_tie.pop()

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

    global binary
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
