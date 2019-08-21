import argparse
import enum
import logging
import os
import pdb
import random
import signal
import struct
import subprocess as sp
import time
from math import sqrt, log, ceil, inf
from typing import Dict, List

from angr import Project
from angr.exploration_techniques import DFS, Explorer
from angr.sim_state import SimState as State
from angr.storage.file import SimFileStream


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
#    pdb.set_trace()
    return simgr.deadended

def solve(state):
    return state.solver.eval(state.solver.constraints[0].args[0])

def explore():
    states = symex()
    vals = [solve(state) for state in states]



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
