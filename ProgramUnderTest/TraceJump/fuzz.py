import sys
import random
from math import sqrt, log

import subprocess32, struct

U = 0.5
C = sqrt(2)

samples = 10
max_rounds = 100

total = 0
max_iterations = 10


class Node():

    def __init__(self, path):
        assert(path)
        
        self.addr = path[-1]
        self.path = path
        self.children = {}
        self.distinct = 1
        self.visited = 1

    def update(self, distinct, visited):
        self.distinct += distinct
        self.visited += visited
        
    def insert(self, suffix):
        if suffix:
            pos = suffix[0]
            rest = suffix[1:]
            
            if not pos in self.children:
                path = self.path + (pos,)
                child = Node(path)
                self.children[pos] = child
            else:
                child = self.children[pos]
                
            child.insert(rest)
        
    def pp(self, indent=0):
        i = "  "  * indent
        
        s = i
        s += hex(self.addr)
        s += " "
        
        s += "(" + str(self.distinct) + "/" + str(self.visited) + ")"
        s += " "
        
        s += "uct = " + str(uct(self))
        s += " "
        
        print(s)
        
        if len(self.children) > 1:
            indent += 1
            
        for child in self.children.values():
            child.pp(indent)


def generate_random(seed):
    bytes = [ random.randint(0, 255) for x in seed ]  # WTF Python: range is inclusive
    input = "".join(map(chr, bytes))
    return input


def mutate(prefix, program, seed, samples):
    global max_rounds
    result = []
    rounds = 0
    print('generating inputs for prefix ' + str(map(hex, prefix)))
    while len(result) < samples and rounds < max_rounds:
        rounds += 1
        input = generate_random(seed)
        path = program(input)
        n = len(prefix)
        if path[:n] == prefix:
            print('using input "' + input + '" with path ' + str(map(hex, path)))
            result.append(path)
        else:
            print('discarding input with path ' + str(map(hex, path)))
    return result


def uct(node):
    global total
    assert(total > 0)
    assert(node.visited > 0)
    exploit = node.distinct / node.visited
    explore = sqrt(log(total) / node.visited)
    return exploit + C * explore


def dice():
    return random.random()


def sample(node, program, seed):
    global total, samples
    if not node.children or dice() < U:
        suffixes = playout(node, program, seed, samples)
        node.distinct += len(suffixes)
        node.visited += samples
        total += samples
        for suffix in suffixes:
            node.insert(suffix)
    else:
        child = max(node.children.values(), key=uct)
        return sample(child, program, seed)


def playout(node, program, seed, samples):
    prefix = node.path
    n = len(prefix)
    
    paths = mutate(prefix, program, seed, samples)
    suffixes = { p[n:] for p in paths }
    return suffixes


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
    return addrs 


def run(binary, seed):
    global max_iterations
    
    program = traced(binary)
    
    # obtain address of main function for the root node by sampling the seed  
    path = program(seed)
    path = path[0:1]
    root = Node(path)

    for i in xrange(max_iterations):
        sample(root, program, seed)
        print('')
        root.pp()
        print('')
        print('')

        
if __name__ == "__main__" and len(sys.argv) > 1:
    binary = sys.argv[1]
    args = sys.argv[2:]
    seed = ''.join(sys.stdin.readlines())
    print('seed')
    print(seed)
    run(binary, seed)
