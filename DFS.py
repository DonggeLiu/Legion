import argparse
import logging
import os
import pdb
import struct
import subprocess as sp
from typing import Dict, List

from angr import Project
from angr.exploration_techniques import DFS, Explorer


# Execution
BINARY = None

# Logging
LOGGER = logging.getLogger("Legion")
LOGGER.setLevel(logging.INFO)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)


def symex():
    project = Project(thing=BINARY, ignore_functions=['printf'])
    simgr = project.factory.simgr(project.factory.entry_state())
    # simgr.use_technique(tech=DFS)
    simgr.explore()
    return simgr.deadended


def solve(state):
    return state.solver.eval(state.solver.constraints[0].args[0])


def explore():
    states = symex()
    vals = [solve(state) for state in states]
    return vals


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
            LOGGER.error("Binary execution time out")
            exit(2)

    global FOUND_BUG, MSGS, INPUTS, TIMES

    report = execute()
    assert bool(report)

    report_msg, return_code = report
    error_msg = report_msg[1]

    return unpack(error_msg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Legion')
    parser.add_argument("file", help='Binary or source file')
    args = parser.parse_args()

    is_c = args.file[-2:] == '.c'
    is_i = args.file[-2:] == '.i'
    is_source = is_c or is_i
    if is_source:
        source = args.file
        stem = source[:-2]
        BINARY = stem + '.instr'
        LOGGER.info('Building {}'.format(BINARY))
        os.system("make {}".format(BINARY))
    else:
        BINARY = args.file

    vals = [val for val in explore()]
    print([binary_execute(bytes([val])) for val in vals])
