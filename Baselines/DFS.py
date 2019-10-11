#!/usr/bin/env python3

import argparse
import logging
import os
import pdb
import struct
import subprocess as sp
from typing import List

from angr import Project
from angr.analyses.identifier.identify import Identifier
from angr.errors import SimProcedureError, SimMemoryAddressError, SimUnsatError
from angr.state_plugins import SimSystemPosix
from angr.storage.file import SimFileStream

# Execution
BINARY = None

# Logging
LOGGER = logging.getLogger("Legion")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)
logging.getLogger('angr').setLevel('ERROR')


def explore():
    project = Project(thing=BINARY, ignore_functions=['printf', '__stack_chk_fail'])
    entry1 = project.factory.entry_state(stdin=SimFileStream)

    # entry = Identifier.make_symbolic_state(entry.project, entry.project.arch.default_symbolic_registers)
    entry = Identifier.make_initial_state(project=project, stack_length=80)

    last_addr = entry.project.loader.main_object.max_addr
    actual_brk = (last_addr - last_addr % 0x1000 + 0x1000)
    entry.register_plugin('posix',
                          SimSystemPosix(stdin=SimFileStream(name='stdin', has_end=False),
                                         brk=actual_brk))

    symex_paths = my_symex(entry)
    # symex_paths = symex(project, entry)

    values = [solve_inputs(path[-1]) for path in symex_paths]
    conex_results = [my_conex(value) for value in values]
    for i in range(len(symex_paths)):
        conex_path, return_code = conex_results[i]
        print("INPUT value: {}; INPUT bytes: {}; RETURN code: {}"
              .format(int.from_bytes(values[i], 'big', signed=True),
                      values[i],
                      return_code))
        print("SymEx".rjust(9), "ConEx".ljust(9), "Constraints")
        for node in symex_paths[i]:
            constraints = node.solver.constraints
            if conex_path and hex(node.addr) == conex_path[0]:
                print(hex(node.addr).rjust(9),
                      conex_path[0].ljust(9),
                      constraints)
                conex_path.pop(0)
            else:
                print(hex(node.addr).rjust(9), ''.rjust(9), constraints)
        for addr in conex_path:
            print("ConEx addr not in SymEx:", addr)
        print()


def my_symex(root):
    def symex_step():
        try:
            successors = node.step().successors
        except (SimProcedureError, SimMemoryAddressError, SimUnsatError) as e:
            print(root, e)
            successors = []
            pdb.set_trace()
        return successors

    paths = [[root]]

    for path in paths:
        node = path[-1]
        children = symex_step()
        while children:
            node = children.pop()
            path.append(node)
            for child in children:
                paths.append(path + [child])
            children = symex_step()

    return paths


def solve_inputs(leaf):
    def solve(state):
        target = state.posix.stdin.load(0, state.posix.stdin.size)
        return state.solver.eval(target), (target.size() + 7) // 8

    solution, byte_len = solve(state=leaf)
    value = solution.to_bytes(byte_len, 'big')
    return value


def my_conex(value):
    conex_path = concrete_execute(value)
    return conex_path


def concrete_execute(input_bytes: bytes) -> (List[str], int):
    """
    Execute the binary with an input in bytes
    :param input_bytes: the input to feed the binary
    :return: the execution trace in a list
    """

    def unpack(output):
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

    report = execute()
    report_msg, return_code = report
    error_msg = report_msg[1]
    trace = unpack(error_msg)
    return [hex(addr) for addr in trace], return_code


def symex(project, entry):
    """
    ANGR's default exploration strategy, DFS according to doc
    :return: the termination states
    """
    simgr = project.factory.simgr(entry)
    # simgr.use_technique(tech=DFS)
    simgr.explore()
    return simgr.deadended

# def save_news_to_file(are_new):
#     """
#     Save data to file only if it is new
#     :param are_new: a list to represent whether each datum
#                     contributes to a new path
#     """
#     global MSGS, INPUTS, TIMES
#     if not SAVE_TESTCASES and not SAVE_TESTINPUTS:
#         return
#
#     if SAVE_TESTCASES:
#         debug_assertion(len(are_new) == len(TIMES) == len(MSGS))
#     if SAVE_TESTINPUTS:
#         debug_assertion(len(are_new) == len(TIMES) == len(INPUTS))
#
#     for i in range(len(are_new)):
#         if are_new[i] and SAVE_TESTCASES:
#             save_tests_to_file(TIMES[i], MSGS[i])
#         if are_new[i] and SAVE_TESTINPUTS:
#             save_input_to_file(TIMES[i], INPUTS[i])
#     MSGS, INPUTS, TIMES = [], [], []
#
#
# def save_tests_to_file(time_stamp, data):
#     # if DIR_NAME not in os.listdir('tests'):
#     os.system("mkdir -p tests/{}".format(DIR_NAME))
#
#     with open('tests/{}/{}_{}'.format(
#             DIR_NAME, time_stamp, SOLVING_COUNT), 'wt') as input_file:
#         input_file.write(
#             '<?xml version="1.0" encoding="UTF-8" standalone="no"?>')
#         input_file.write(
#             '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" "https://sosy-lab.org/test-format/testcase-1.1.dtd">')
#         input_file.write('<testcase>\n')
#         input_file.write(data)
#         input_file.write('</testcase>\n')
#
#
# def save_input_to_file(time_stamp, input_bytes):
#     # if DIR_NAME not in os.listdir('inputs'):
#     os.system("mkdir -p inputs/{}".format(DIR_NAME))
#
#     with open('inputs/{}/{}_{}'.format(
#             DIR_NAME, time_stamp, SOLVING_COUNT), 'wb') as input_file:
#         input_file.write(input_bytes)
#
#
# def debug_assertion(assertion: bool) -> None:
#     if LOGGER.level <= logging.INFO and not assertion:
#         pdb.set_trace()
#         return
#     assert assertion
#
#
# def handle_timeout() -> None:
#     LOGGER.info("{} seconds time out!".format(MAX_TIME))
#     exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Legion')
    # parser.add_argument('--min-samples', type=int, default=MIN_SAMPLES,
    #                     help='Minimum number of samples per iteration')
    # parser.add_argument('--max-samples', type=int, default=MAX_SAMPLES,
    #                     help='Maximum number of samples per iteration')
    # parser.add_argument('--time-penalty', type=float, default=TIME_COEFF,
    #                     help='Penalty factor for constraints that take longer to solve')
    # # parser.add_argument('--sv-comp', action="store_true",
    # #                     help='Link __VERIFIER_*() functions, *.i files implies --source')
    # # parser.add_argument('--source', action="store_true",
    # #                     help='Input file is C source code (implicit for *.c)')
    # # parser.add_argument('--cc',
    # #                     help='Specify compiler binary')
    # # parser.add_argument('--as',
    # #                     help='Specify assembler binary')
    # parser.add_argument('--save-inputs', type=bool, default=SAVE_TESTINPUTS,
    #                     help='Save inputs as binary files')
    # parser.add_argument('--save-tests', type=bool, default=SAVE_TESTCASES,
    #                     help='Save inputs as TEST-COMP xml files')
    # parser.add_argument('-v', '--verbose', action="store_true",
    #                     help='Increase output verbosity')
    parser.add_argument("file",
                        help='Binary or source file')
    # parser.add_argument("seeds", nargs='*',
    #                     help='Optional input seeds')
    args = parser.parse_args()

    # MIN_SAMPLES = args.min_samples
    # MAX_SAMPLES = args.max_samples
    # TIME_COEFF = args.time_penalty
    # SAVE_TESTINPUTS = args.save_inputs
    # SAVE_TESTCASES = args.save_tests

    # if args.verbose:
    #     #     LOGGER.setLevel(logging.DEBUG)

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

    # binary_name = BINARY.split("/")[-1]
    # DIR_NAME = "{}_{}_{}_{}".format(
    #     binary_name, MIN_SAMPLES, TIME_COEFF, TIME_START)
    #
    # SEEDS = args.seeds
    #
    # signal.signal(signal.SIGALRM, handle_timeout())
    # signal.alarm(MAX_TIME)
    #
    # run()
    # ROOT.pp()
    print(explore())
