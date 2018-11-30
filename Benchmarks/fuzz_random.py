import sys
import tracer
import random
from math import sqrt, log

import subprocess32, struct

# C = sqrt(2)
C = 1/sqrt(2)

samples = 1
max_rounds = 100

total = 30
max_iterations = float('inf')
max_path = 9

iter_count = 0

class Node():

    def __init__(self, path, dummy=False):
        assert(path)
        
        self.path = path
        self.children = {} # {addr: Node(tuple(path up to addr))}?
        if not dummy:
            self.children['Simulation'] = Node(path, dummy=True)
        self.distinct = 0.
        self.visited = 0. 

    def is_path_node(self):
    	return 'Simulation' in self.children

    def update(self, distinct, visited):
        self.distinct += distinct
        self.visited += visited

    def insert(self, path):
        """
        path represents the full path from root to leaf
        """
        self.visited += 1
        starts_new_path = False

        if not path:
        	return starts_new_path

        child_addr = path[0]

        if child_addr not in self.children.keys(): # new child
            self.children[child_addr] = Node(self.path + (child_addr,))
            self.children['Simulation'].distinct += 1
            starts_new_path = True

        starts_new_path = self.children[child_addr].insert(path[1:]) or starts_new_path
        self.distinct += starts_new_path
        return starts_new_path

    def info(self):
        return '{NodeType}: {NodePath}'.format(
            NodeType='PathNode' if self.is_path_node() else 'SimulationChild',
            NodePath=[hex(addr) if addr else 'Root' for addr in self.path])
        
    def pp(self, indent=0):
        i = "  "  * indent
        
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
            
        for addr,child in self.children.items():
            child.pp(indent)


def generate_random(seed):
    bytes = [ random.randint(0, 255) for x in seed ]  # WTF Python: range is inclusive
    input = "".join(map(chr, bytes))
    return input


def mutate(prefix, program, seed, samples):
    global max_rounds
    result = []
    rounds = 0

    # print('generating inputs for prefix ' + str(map(hex, prefix)))
    while len(result) < samples and rounds < max_rounds:
        rounds += 1
        input = generate_random(seed)
        path = program(input)
        n = len(prefix)
        if path[:n] == prefix:
            # print('using input "' + input + '" with path ' + str(map(hex, path)))
            result.append(path)
        else:
        	pass
          # print('discarding input with path ' + str(map(hex, path)))
    return result


def uct(node):
    global total
    assert(total > 0)
    assert(node.visited >= 0)
    if not node.visited:
        return float('inf')
    exploit = (node.distinct / node.visited)
    explore = (sqrt(log(total) / node.visited))
    # return exploit + C * explore
    # print(node.info())
    if node.is_path_node():
    	return max(exploit + C * explore, uct(node.children['Simulation']))
    return exploit + C * explore

def playout_full(node, program, seed):
    prefix = node.path[1:]
    n = len(prefix)
    paths = mutate(prefix, program, seed, samples)
    
    return [path for path in paths if path] # paths starts from node.child


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
    runner = tracer.qemu_runner.QEMURunner(binary, input)
    addrs = runner.trace
    return addrs


def run(binary, seed):
    global max_iterations
    program = traced(binary)

    root = Node((None,))
    iter_count = 0
    # while max_iterations:
    #     mcts(root, program, seed)
    #     max_iterations -= 1
    #     root.pp()
    pre = 0
    while root.distinct < max_path:
    	mcts(root, program, seed)
    	iter_count += 1
    	if root.distinct != pre:
    		print("{},{}".format(iter_count, root.distinct))
    		pre == root.distinct
    	if iter_count >= max_iterations:
    		break
    	# iter_count += 1
    	# print("{}, {}".format(iter_count, root.distinct))
      # mcts(root, program, seed)
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
    
    node = root
    # while node.children:
    # 	node = best_child(node) # will always be a sim_node

    # print('Tree policy gives node = {}'.format(node.info()))
    paths = playout_full(root, program, seed) # Full path
    num_win, num_sim = 0, len(paths)
    for path in paths:
        num_win += root.insert(path)

    node.visited += num_sim
    # print(node.info())

def best_child(node):
	uct_tie = []
	max_score = None
	for child in node.children.values():
		if not max_score:
			max_score = uct(child)
			uct_tie.append(child)
			continue

		cur_score = uct(child)
		if max_score == cur_score:
			uct_tie.append(child)
			continue

		if cur_score > max_score:
			max_score = cur_score
			uct_tie = [child]

	assert(uct_tie)

	if len(uct_tie) == 1:
		return uct_tie.pop()


	win_tie = []
	max_win= None
	for child in uct_tie:
		if not max_win:
			max_win = child.distinct
			win_tie.append(child)
			continue
		if max_win == child.distinct:
			win_tie.append(child)
			continue
		if child.distinct > max_win:
			win_tie = [child]

	assert(win_tie)
	if len(win_tie) == 1:
		return win_tie.pop()

	assert(win_tie)
	vis_tie = []
	min_vis = None
	for child in win_tie:
		if not min_vis:
			min_vis = child.visited
			vis_tie.append(child)
			continue
		if min_vis == child.visited:
			vis_tie.append(child)
			continue
		if child.visited < vis_tie:
			vis_tie = [child]


	assert(vis_tie)
	if len(vis_tie) == 1:
		return vis_tie.pop()

	for child in vis_tie:
		if not child.is_path_node():
			return child
	return vis_tie.pop()


def simulate(node, program, seed):
    suffixes = playout(node, program, seed) # suffix starts from node.child
    
    num_win = sum([node.parent.insert(suffix) for suffix in suffixes])
    num_sim = len(suffixes)
    
    return num_win, num_sim


        
if __name__ == "__main__" and len(sys.argv) > 1:
    binary = sys.argv[1]
    args = sys.argv[2:]
    seed = ''.join(args)
    # print('seed')
    # print(seed)
    run(binary, seed)

