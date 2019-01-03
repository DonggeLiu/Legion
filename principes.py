import logging
import pdb
import random
import re
import struct
import subprocess
import sys
import time
from math import sqrt, log

import angr
import claripy

from Results.pie_maker import make_pie

MAX_PATHS = 9
NUM_SAMPLES = 5
DSC_PATHS = set()
PST_INSTRS = set()
MAX_ROUNDS = 100
CUR_ROUND = 0
SAMPLES_COUNT = 0

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
SEEDS = [str.encode(''.join(sys.argv[2:]))]
PROJ = None

LOGGER = logging.getLogger("lg")
LOGGER.setLevel(logging.DEBUG)


def generate_random():
    # in_str = "".join(map(chr, [random.randint(0, 255) for _ in SEED]))
    return random.randint(0, 255)


class TreeNode:
    """
    NOTE:
        Node colour:
            White:  In TraceJump     + Not sure if in Angr   + check Symbolic state later    + may have simulation child
            Red:    In TraceJump     + Confirmed in Angr     + has Symbolic state            + has Simulation child
            Black:  In TraceJump     + Confirmed not in Angr + No Symbolic state             + No Simulation child
            Gold:   Not in TraceJump + Not in Angr           + Same Symbolic state as parent + is a Simulation child
    """

    def __init__(self, addr, parent=None, state=None, colour='W', symbols=''):
        self.exhausted = False
        self.addr = addr
        self.parent = parent
        self.state = state
        self.colour = colour
        self.constraint = []

        self.children = {}  # {addr: Node}
        self.distinct = 0
        self.visited = 0
        self.symbols = symbols

    def best_child(self):

        max_score = -float('inf')
        candidates = []
        for child in self.children.values():
            child = child.next_non_black_child()
            child_score = uct(child)
            print(child, child_score)
            if child_score == max_score:
                candidates.append(child)
            if child_score > max_score:
                max_score = child_score
                candidates = [child]

        return random.choice(candidates)

    def next_non_black_child(self):
        if self.colour is not 'B':
            return self
        if not self.children:
            return self
        if len(self.children) == 1:
            return self.children[list(self.children.keys())[0]].next_non_black_child()
        return self.best_child()

    def dye_to_nearest_red_child(self):
        """
        First find the nearest red parent as starting point of simulation manager
        Then use it to compute the symbolic state of self and self's decedents
        return if the first red node is found
        """
        assert self.colour is 'W'

        # First find red parent
        parent, path = self.track_nearest_red_parent()
        if parent is self:  # self the same as red parent, so it has already been dyed as red (Root?)
            assert self.parent is None
            return

        # dye the way down along the path
        assert PROJ
        simgr = prepare_simgr(entry=parent.state)
        # simgr = PROJ.factory.simulation_manager(parent.state, save_unsat=True)
        found_red_child = False
        while not found_red_child:
            if not parent.children:  # leaf
                break
            addr = path.pop() if path else random.choice(list(parent.children.keys()))
            child = parent.children.get(addr)
            assert child
            child.dye(simgr=simgr)
            if child.colour is 'R':
                return
            parent = child
        assert self.colour is not 'W'
        assert self.colour is 'B' or self.state

    def track_nearest_red_parent(self):
        node, path = self, []
        while node.parent and (not node.state):
            path.append(node.addr)
            # if not node.parent:  # Root
            #     break
            node = node.parent
        path.append(node.addr)

        assert node.state
        # if not node.state:
        #     assert not node.parent  # Root before SEED
        #     node.state = PROJ.factory.entry_state(addr=node.addr, stdin=angr.storage.file.SimFileStream)
        #     node.children['Simulation'] = TreeNode(addr=self.addr, parent=self, state=self.state, colour='G')
        #     node.colour = 'R'
        assert node and (node.colour is 'R') and node.state and (node.addr is path.pop())
        # pop out path[-1], which should be the addr of node and will not be needed
        return node, path

    def dye(self, simgr):
        self.attach_state(simgr=simgr)
        if self.state:
            self.children['Simulation'] = TreeNode(addr=self.addr, parent=self, state=self.state, colour='G',
                                                   symbols=self.symbols)
            self.children['Simulation'].constraint = self.constraint

    def attach_state(self, simgr):
        identified = False
        assert not self.state
        while simgr.active and not identified:
            for state in simgr.active:
                if self.addr != state.addr:
                    continue
                identified = True
                self.state, self.colour = (state, 'R') if len(simgr.active) > 1 else (None, 'B')
                if self.state:
                    self.compute_constraints()
            simgr.step()
        # assert identified
        if not identified:
            # pdb.set_trace()
            self.state, self.colour = None, 'B'

    def compute_constraints(self):
        if not self.state:
            pdb.set_trace()
        preconstraints = set(self.state.preconstrainer.preconstraints)
        all_constraint = set(self.state.solver.constraints)
        self.constraint = list(all_constraint - preconstraints)
        # for con in self.constraint:
        #     for c in con.args:
        #         if type(c.args[1]) is claripy.ast.BV:
        #             self.symbols = c.args[1].concat(self.symbols)

    def is_exhausted(self):
        return self.exhausted or ('Simulation' in self.children and self.children['Simulation'].exhausted)

    def mutate(self):
        if self.state and self.constraint:
            # TODO: Pass PST_INSTRS to solver
            solver = claripy.Solver(backend=claripy.backends._all_backends[2])
            print("{}'s constraint: {}".format(hex(self.addr), self.constraint))
            # pdb.set_trace()
            solver.add(self.constraint)
            assert solver.constraints == self.constraint
            vals = solver.eval(e=self.state.posix.stdin.load(0, self.state.posix.stdin.size), n=NUM_SAMPLES)

            if None in vals:
                self.exhausted = True

            return vals

        # Must be root in the first round before executing seed:
        assert not self.parent.parent
        return [generate_random() for _ in range(NUM_SAMPLES)]

    def add_child(self, addr):
        if addr in self.children.keys():
            return False
        self.children[addr] = TreeNode(addr=addr, parent=self)
        return True

    def pp(self, indent=0, mark_node=None, found=0):
        s = ""
        for _ in range(indent - 1):
            s += "|   "
        if indent:
            s += "|-- "
        s += str(self)
        if self == mark_node:
            s += "\033[1;32m <= found {}\033[0;m".format(found)
        print(s)
        if self.children:
            indent += 1
        for addr, child in self.children.items():
            child.pp(indent=indent, mark_node=mark_node, found=found)

    def repr_node_name(self):
        return ("Simul Node: " if self.colour is 'G' else "Block Node: ") \
               + (hex(self.addr)[-4:] if self.addr else "None")

    def repr_node_data(self):
        return "{uct:.4f}({distinct:1d}/{visited:1d})".format(
            uct=uct(self), distinct=self.distinct, visited=self.visited)

    def repr_node_state(self):
        return "State: {}".format(self.state if self.state else "None")

    def repr_node_child(self):
        return ["{}: {})".format(child.repr_node_name(), child.repr_node_data())
                for _, child in self.children.items()]

    def __repr__(self):
        return '\033[1;{colour}m{name}: {state}, {data}\033[0m'.format(
            colour=30 if self.colour is 'B' else
            31 if self.colour is 'R' else
            33 if self.colour is 'G' else
            37 if self.colour is 'W' else 32,
            name=self.repr_node_name(),
            state=self.repr_node_state(),
            data=self.repr_node_data(),
            children=self.repr_node_child())


def uct(node):
    if node.is_exhausted():
        return -float('inf')
    if not node.visited:
        return float('inf')
    if 'Simulation' in node.children:
        return uct(node.children['Simulation'])
    exploit = node.distinct / node.visited
    explore = sqrt(log(CUR_ROUND + 1) / node.visited)
    return exploit + RHO * explore


def run():
    global CUR_ROUND

    root = initialisation()
    CUR_ROUND += 1
    root.pp()
    while keep_fuzzing(root):
        mcts(root)
        CUR_ROUND += 1


def initialisation():
    initialise_angr()
    root = TreeNode(addr=None, parent=None, state=None, colour='R')
    root.state = prepare_simgr(entry=root.addr)
    root.state = PROJ.factory.entry_state(addr=root.addr, stdin=angr.storage.file.SimFileStream)
    root.compute_constraints()
    root.children['Simulation'] = TreeNode(addr=root.addr, parent=root, state=root.state, colour='G',
                                           symbols=root.symbols)
    seed_paths = simulation_stage(node=root.children['Simulation'], input_str=SEEDS)
    are_new = expansion_stage(root, seed_paths)
    propagation_stage(root, seed_paths, are_new, [root, root.children['Simulation']])
    return root


def initialise_angr():
    global PROJ
    PROJ = angr.Project(BINARY)


def keep_fuzzing(root):
    LOGGER.info("=== Iter:{} === Root.distinct:{} === len(DSC_PATHS):{} === QS_COUNT:{} ==="
                .format(CUR_ROUND, root.distinct, len(DSC_PATHS), QS_COUNT))
    assert root.distinct == len(DSC_PATHS)
    return len(DSC_PATHS) < MAX_PATHS and CUR_ROUND < MAX_ROUNDS


def mcts(root):
    nodes = selection_stage(root)
    # pdb.set_trace()
    paths = simulation_stage(nodes[-1])
    # NOTE: What if len(paths) < NUM_SAMPLES? i.e. fuzzer finds less mutant than asked
    #  Without handling this, we will be trapped in the infeasible node, whose num_visited is always 0
    #  I saved all nodes along the path of selection stage and used them here
    are_new = expansion_stage(root, paths)
    propagation_stage(root, paths, are_new, nodes, NUM_SAMPLES - len(paths))
    root.pp(indent=0, mark_node=nodes[-1], found=sum(are_new))


def selection_stage(node):
    nodes, prev_red_index = [], 0

    prev_red_node = None
    while node.children:
        print("Select: {}".format(node))
        if node.colour is 'R':
            prev_red_node = node
        if node.colour is 'W':
            node.dye_to_nearest_red_child()
        assert not (node.colour is 'W' or node.colour is 'G')
        # NOTE: No need to differentiate red or black here
        node = node.best_child()
        prev_red_index = len(nodes) if node.colour is 'R' else prev_red_index
        nodes.append(node)

    print("Select: {}".format(node))
    if node.addr and not node.state:
        assert not node.children  # is a leaf
        assert prev_red_node is nodes[prev_red_index]
        print("Select: {} as {} is a leaf".format(prev_red_node, node))
        return nodes[:prev_red_index + 1] + [prev_red_node.children['Simulation']]

    return nodes


def simulation_stage(node, input_str=None):
    mutants = node.mutate()

    print("INPUT_val: {}".format([mutant for mutant in mutants]))
    mutants = input_str if input_str else [str.encode(chr(mutant), 'utf-8', 'surrogatepass')
                                           for mutant in mutants if mutant is not None]
    print("INPUT_STR: {}".format(mutants))
    return [program(mutant) for mutant in mutants]


def program(input_str):
    def unpack(output):
        assert (len(output) % 8 == 0)
        # print([addr for i in range(int(len(output)/8)) for addr in struct.unpack_from('q', output, i * 8)])
        # NOTE: changed addr[0] to addr
        return [addr for i in range(int(len(output) / 8)) for addr in struct.unpack_from('q', output, i * 8)]

    error_msg = subprocess.Popen(BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) \
        .communicate(input_str)[1]
    return unpack(error_msg)


def expansion_stage(root, paths):
    return [expand_path(root, path) for path in paths]


def expand_path(root, path):
    global DSC_PATHS
    DSC_PATHS.add(tuple(path))
    print("INPUT_PATH: {}".format([hex(addr) for addr in path]))

    assert (not root.addr or root.addr == path[0])  # Either Root before SEED or it must have an addr

    if not root.addr:  # NOTE: assign addr to root
        root.addr = path[0]
        root.children['Simulation'].addr = root.addr
    node, is_new = root, False
    for addr in path[1:]:
        is_new = node.add_child(addr) or is_new  # have to put node.child(addr) first to avoid short circuit
        node = node.children[addr]

    return is_new


def propagation_stage(root, paths, are_new, nodes, short=0):
    assert len(paths) == len(are_new)

    # NOTE: If number of inputs generated by fuzzer < NUM_SAMPLES,
    #  then we need to update the node in :param nodes (whose addr might be different from :param paths)
    #  otherwise we might be trapped in some nodes
    for node in nodes:
        node.visited += short
        # node.distinct += sum(are_new)

    for i in range(len(paths)):
        propagate_path(root, paths[i], are_new[i], nodes[-1])


def propagate_path(root, path, is_new, node):
    node.visited += 1
    node.distinct += is_new
    node = root
    assert node.addr == path[0]
    for addr in path[1:]:
        node.visited += 1
        node.distinct += is_new
        assert node.distinct < 10
        if addr not in node.children:
            pdb.set_trace()
        node = node.children.get(addr)
        assert node
    node.visited += 1
    node.distinct += is_new


def prepare_simgr(entry):
    # TODO: modify the code in line 117 of sim_manager.py to avoid duplicated initialisation of simgr
    assert PROJ
    return PROJ.factory.simulation_manager(entry, save_unsat=True)


def make_constraint_readable(constraint):
    con_str = "["
    for con in constraint:
        con_ops = re.search(pattern='<Bool (.*?) [<=>]*? (0x[a-f0-9][a-f0-9])>', string=str(con))
        op_str1 = "INPUT_STR" if 'stdin' in con_ops[1] else str(int(con_ops[1], 16))
        op_str2 = "INPUT_STR" if 'stdin' in con_ops[2] else str(int(con_ops[2], 16))
        con_str += con_ops[0].replace(con_ops[1], op_str1).replace(con_ops[2], op_str2)
        con_str += ", "

    return con_str + "]"


if __name__ == "__main__" and len(sys.argv) > 1:
    assert BINARY and SEEDS
    start = time.time()
    iter_count = run()[-1][0]
    end = time.time()

    assert iter_count
    categories = ['Iteration',
                  'Samples Num',
                  'Total Time',
                  'Initialisation',
                  'Binary Execution',
                  'Symbolic Execution',
                  'Path Preserve Fuzzing',
                  'Random Fuzzing',
                  'TreePolicy',
                  'TreeExpansion',
                  'Constraint Reading']

    values = [iter_count,
              NUM_SAMPLES * iter_count,
              end - start,
              ANGR_TIME,
              SIMLTR_TIME,
              TRACER_TIME,
              QS_TIME,
              RD_TIME,
              TREE_POLICY_TIME,
              EXPANSION_TIME,
              CONSTRAINT_PARSING_TIME]

    averages = ['/',
                '/',
                (end - start) / (iter_count * NUM_SAMPLES),
                ANGR_TIME / (iter_count * NUM_SAMPLES),
                SIMLTR_TIME / (iter_count * NUM_SAMPLES),
                TRACER_TIME / (iter_count * NUM_SAMPLES),
                QS_TIME / QS_COUNT,
                RD_TIME / RD_COUNT,
                TREE_POLICY_TIME / iter_count,
                EXPANSION_TIME / (iter_count * NUM_SAMPLES),
                CONSTRAINT_PARSING_TIME / MAX_PATHS]

    if not len(categories) == len(values) == len(averages):
        pdb.set_trace()

    # logging_results()

    make_pie(categories=categories, values=values, averages=averages)

    assert (len(DSC_PATHS) == MAX_PATHS)
