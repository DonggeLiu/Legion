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

from Results.pie_maker import make_pie

MAX_PATHS = 9
MAX_ROUNDS = 100
NUM_SAMPLES = 5

DSC_PATHS = set()
PST_INSTRS = set()
CUR_ROUND = 0

RHO = 1 / sqrt(2)

QS_COUNT = 0
RD_COUNT = 0
BINARY_EXECUTION_COUNT = 0
SYMBOLIC_EXECUTION_COUNT = 0

TIME_LOG = {}

BINARY = sys.argv[1]
SEEDS = [str.encode(''.join(sys.argv[2:]))]
PROJ = None

LOGGER = logging.getLogger("Principes")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)


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


def generate_random():
    return [random.randint(0, 255) for _ in SEEDS[0]]


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
            LOGGER.info("\033[0mCandidate: {}\033[0m".format(child))
            if child_score == max_score:
                candidates.append(child)
            if child_score > max_score:
                max_score = child_score
                candidates = [child]

        return random.choice(candidates)

    @timer
    def next_non_black_child(self):
        if self.colour is not 'B':
            return self
        if not self.children:
            return self
        if len(self.children) == 1:
            return self.children[list(self.children.keys())[0]].next_non_black_child()
        return self.best_child()

    @timer
    def dye(self, colour, state=None):
        assert self.colour is 'W'
        assert (colour is 'B' and not state) or (colour is 'R' and state)

        self.colour = colour
        if colour is 'R':
            self.state = state
            self.children['Simulation'] = TreeNode(addr=self.addr, parent=self, state=self.state, colour='G')
        LOGGER.info("Dye {}".format(self))

    def is_diverging(self):
        # Return if self is a diverging node in the current incomplete tree
        return (len(self.children) - ('Simulation' in self.children)) > 1

    def mark_exhausted(self):
        assert not self.exhausted
        self.exhausted = True
        if self.colour is 'R':
            self.children['Simulation'].exhausted = True
        else:
            assert self.colour is 'G'
            self.parent.exhausted = True

    def is_exhausted(self):
        return self.exhausted or ('Simulation' in self.children and self.children['Simulation'].exhausted)

    @timer
    def mutate(self):
        if self.state.solver.constraints:
            return self.quick_sampler()
        return self.random_sampler()

    @timer
    def quick_sampler(self):
        global QS_COUNT
        QS_COUNT += NUM_SAMPLES
        LOGGER.info("{}'s constraint: {}".format(
            hex(self.addr), make_constraint_readable(self.state.solver.constraints)))

        target = self.state.posix.stdin.load(0, self.state.posix.stdin.size)
        vals = self.state.solver.eval_upto(e=target, n=NUM_SAMPLES)

        if len(vals) < NUM_SAMPLES:
            self.exhausted = True
        n = (target.size() + 7) // 8  # Round up to the next full byte
        result = [x.to_bytes(n, 'big') for x in vals]  # 'Big' is default order of z3 BitVecVal

        return result

    @timer
    def random_sampler(self):
        global RD_COUNT
        RD_COUNT += NUM_SAMPLES
        # Must be root in the first round before executing seed:
        assert not self.parent.parent
        return [generate_random() for _ in range(NUM_SAMPLES)]

    def add_child(self, addr):
        if addr in self.children.keys():
            return False
        self.children[addr] = TreeNode(addr=addr, parent=self)
        return True

    @timer
    def pp(self, indent=0, mark_node=None, found=0):
        s = ""
        for _ in range(indent - 1):
            s += "|   "
        if indent > 32:
            LOGGER.info("...")
            return
        if indent:
            s += "|-- "
        s += str(self)
        if self == mark_node:
            s += "\033[1;32m <=< found {}\033[0;m".format(found)
        LOGGER.info(s)
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


@timer
def run():
    global CUR_ROUND
    history = []
    root = initialisation()
    CUR_ROUND += 1
    root.pp()
    while keep_fuzzing(root):
        history.append([CUR_ROUND, root.distinct])
        mcts(root)
        CUR_ROUND += 1
    return history


@timer
def initialisation():
    initialise_angr()
    return initialise_seeds(TreeNode(addr=None, parent=None, state=None, colour='R'))


@timer
def initialise_angr():
    global PROJ
    PROJ = angr.Project(BINARY)


@timer
def initialise_seeds(root):
    root.state = prepare_simgr(entry=root.addr)
    root.state = PROJ.factory.entry_state(addr=root.addr, stdin=angr.storage.file.SimFileStream)
    root.children['Simulation'] = TreeNode(
        addr=root.addr, parent=root, state=root.state, colour='G', symbols=root.symbols)
    seed_paths = simulation_stage(node=root.children['Simulation'], input_str=SEEDS)
    are_new = expansion_stage(root, seed_paths)
    propagation_stage(root, seed_paths, are_new, [root, root.children['Simulation']])
    return root


def keep_fuzzing(root):
    LOGGER.info("\033[1;35m== Iter:{} == Tree path:{} == Set path:{} "
                "== SAMPLE_COUNT:{} == QS: {} == RD: {} ==\033[0m"
                .format(CUR_ROUND, root.distinct, len(DSC_PATHS),
                        BINARY_EXECUTION_COUNT, QS_COUNT, RD_COUNT))
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


@timer
def selection_stage(node):
    nodes, prev_red_index = tree_policy(node=node)
    if nodes[-1].state:
        return nodes

    assert nodes[-1].addr and not nodes[-1].children  # is a leaf
    return tree_policy_for_leaf(nodes=nodes, red_index=prev_red_index)


@timer
def tree_policy(node):
    nodes, prev_red_index, last_state = [], 0, PROJ.factory.entry_state(stdin=angr.storage.file.SimFileStream)

    while node.children:
        LOGGER.info("\033[1;32mSelect\033[0m: {}".format(node))
        nodes.append(node)
        assert not node.parent or node.parent.colour is 'R' or node.parent.colour is 'B'
        if node.colour is 'W':
            dye_to_the_next_red(start_node=node, last_state=last_state)
        if node.colour is 'R':
            last_state = node.state
        # NOTE: No need to distinguish red or black here
        node = node.best_child()
        prev_red_index = len(nodes) if node.colour is 'R' else prev_red_index
    nodes.append(node)
    LOGGER.info("Select: {}".format(nodes[-1]))
    return nodes, prev_red_index


def dye_to_the_next_red(start_node, last_state):

    succs = compute_line_children_states(state=last_state)
    while True:
        dye_red_black_node(start_node, target_states=succs)
        if start_node.is_diverging() or not start_node.children:
            break
        start_node = next(v for v in start_node.children.values())


def compute_line_children_states(state):
    """
    Symbolically execute to the end of the line of the state
    :param state: the state which is in the line to execute through
    :return: a list of the immediate children states of the line,
        could be empty if the line is a leaf
    """
    children = symbolic_execute(state=state)
    ls = []
    while len(children) == 1:
        ls.append(children[0])
        children = symbolic_execute(state=children[0])
    return children


def dye_red_black_node(candidate_node, target_states):
    for state in target_states:
        if candidate_node.addr == state.addr:
            candidate_node.dye(colour='R', state=state)
            break
    if candidate_node.colour is 'R':
        return
    candidate_node.dye(colour='B')


@timer
def symbolic_execute(state):
    global SYMBOLIC_EXECUTION_COUNT
    SYMBOLIC_EXECUTION_COUNT += 1
    return state.step().successors


@timer
def tree_policy_for_leaf(nodes, red_index):
    # NOTE: Roll back to the immediate red ancestor
    #  and only keep the path from root the that ancestor's simulation child
    LOGGER.info("Select: {} as {} is a leaf".format(nodes[red_index], nodes[-1]))

    # assert node is red and has simulation child
    assert nodes[red_index].colour is 'R' and 'Simulation' in nodes[red_index].children
    return nodes[:red_index + 1] + [nodes[red_index].children['Simulation']]


@timer
def simulation_stage(node, input_str=None):
    mutants = input_str if input_str else node.mutate()

    LOGGER.info("INPUT_val: {}".format(mutants))
    mutants = [bytes(mutant) for mutant in mutants if mutant is not None]
    LOGGER.info("INPUT_bytes: {}".format(mutants))
    return [program(mutant) for mutant in mutants]


@timer
def program(input_str):
    global BINARY_EXECUTION_COUNT
    BINARY_EXECUTION_COUNT += 1

    def unpack(output):
        assert (len(output) % 8 == 0)
        # NOTE: changed addr[0] to addr
        return [addr for i in range(int(len(output) / 8))
                for addr in struct.unpack_from('q', output, i * 8)]

    error_msg = subprocess.Popen(
        BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE).communicate(input_str)[1]
    return unpack(error_msg)


@timer
def expansion_stage(root, paths):
    return [expand_path(root, path) for path in paths]


@timer
def expand_path(root, path):
    global DSC_PATHS
    DSC_PATHS.add(tuple(path))
    LOGGER.info("INPUT_PATH: {}".format([hex(addr) for addr in path]))

    assert (not root.addr or root.addr == path[0])  # Either Root before SEED or it must have an addr

    if not root.addr:  # NOTE: assign addr to root
        root.addr = path[0]
        root.children['Simulation'].addr = root.addr
    node, is_new = root, False
    for addr in path[1:]:
        is_new = node.add_child(addr) or is_new  # have to put node.child(addr) first to avoid short circuit
        node = node.children[addr]

    return is_new


@timer
def propagation_stage(root, paths, are_new, nodes, short=0):
    assert len(paths) == len(are_new)

    # NOTE: If number of inputs generated by fuzzer < NUM_SAMPLES,
    #  then we need to update the node in :param nodes (whose addr might be different from :param paths)
    #  otherwise we might be trapped in some nodes
    for node in nodes:
        node.visited += short

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
        assert node.distinct <= MAX_PATHS
        if addr not in node.children:
            pdb.set_trace()
        node = node.children.get(addr)
        assert node
    node.visited += 1
    node.distinct += is_new


def make_constraint_readable(constraint):
    con_str = "["
    for con in constraint:
        con_ops = re.search(pattern='<Bool (.*?) [<=>]*? (.*)>', string=str(con))
        op_str1 = "INPUT_STR" if 'stdin' in con_ops[1] \
            else str(int(con_ops[1], 16) if '0x' in con_ops[1] else con_ops[1])
        op_str2 = "INPUT_STR" if 'stdin' in con_ops[2] \
            else str(int(con_ops[2], 16) if '0x' in con_ops[2] else con_ops[2])
        con_str += con_ops[0].replace(con_ops[1], op_str1).replace(con_ops[2], op_str2)
        con_str += ", "

    return con_str + "]"


def display_results():
    for i in range(len(categories)):
        print("{:25s}: {:-9.6f} / {:-3d} = {:3.6f}"
              .format(categories[i], values[i], units[i], averages[i]))


if __name__ == "__main__" and len(sys.argv) > 1:
    assert BINARY and SEEDS

    LOGGER.info(BINARY)
    LOGGER.info(SEEDS)

    ITER_COUNT = run()[-1][0]
    for key, val in TIME_LOG.items():
        LOGGER.info("{:25s}: {}".format(key, val))

    assert ITER_COUNT
    categories = ['Iteration Number',
                  'Samples Number / iter',
                  'Total',
                  'Initialisation',
                  'Binary Execution',
                  'Symbolic Execution',
                  'Path Preserve Fuzzing',
                  'Random Fuzzing',
                  'Tree Policy',
                  'Tree Expansion'
                  ]

    values = [ITER_COUNT,
              NUM_SAMPLES,
              TIME_LOG['run'],  # Time
              TIME_LOG['initialisation'],  # Initialisation
              TIME_LOG['program'],  # Binary execution
              TIME_LOG['dye'],  # Symbolic execution
              TIME_LOG['quick_sampler'],  # Quick sampler
              TIME_LOG['random_sampler'],  # Random sampler
              TIME_LOG['selection_stage'] - TIME_LOG['dye_to_nearest_red_child'],  # Tree policy
              TIME_LOG['expansion_stage']  # Expansion
              ]

    units = [1,
             1,
             ITER_COUNT * NUM_SAMPLES,  # Time
             ITER_COUNT * NUM_SAMPLES,  # Initialisation
             BINARY_EXECUTION_COUNT,  # Binary execution
             SYMBOLIC_EXECUTION_COUNT,  # Symbolic execution
             QS_COUNT,  # Quick sampler
             RD_COUNT,  # Random sampler
             ITER_COUNT,  # Tree Policy
             MAX_PATHS  # Expansion time
             ]

    averages = [values[i] / units[i] for i in range(len(values))]

    if not len(categories) == len(values) == len(units) == len(averages):
        pdb.set_trace()

    if len(DSC_PATHS) != MAX_PATHS:
        pdb.set_trace()

    display_results()
    make_pie(categories=categories, values=values, units=units, averages=averages)
