#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import signal
import struct
import subprocess as sp
import sys
import time
import random
import pdb
from typing import List

from multiprocessing import Pool, cpu_count
from angr import Project
from angr.exploration_techniques import DFS
from angr.errors import SimProcedureError, SimMemoryAddressError, SimUnsatError
from angr.storage.file import SimFileStream

BINARY = None
SAVE_TESTCASES = False
SAVE_TESTINPUTS = False
TIME_START = time.time()
MAX_TIME = 0
SYMEX_TIMEOUT = 0  # in secs
CONEX_TIMEOUT = None  # in secs
# PATH_COUNT = 0
SIMPOOL = None
RAN_SEED = 0

# Logging
LOGGER = logging.getLogger("SymbolicExecution")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)
logging.getLogger('angr').setLevel('ERROR')


def main() -> int:
    """
    MAX_TIME == 0: Unlimited time budget
    MAX_TIME >  0: Time budget is MAX_TIME
    """
    simgr = init_project()
    path = concrete_execute(b'\x00'*10)[0]
    print(path)
    # while simgr.active:
    #     print(simgr.active)
    #     simgr.step()

    for addr in path:
        # while simgr.active and addr not in [node.addr for node in simgr.active]:
        #     print([(node.addr, addr, node.addr == addr) for node in simgr.active])
        #     simgr.step()
        simgr.step(until=lambda sm: len(sm.acitve) > 1)
        print(simgr.active)
        for node in simgr.active:
            if node.addr != addr:
                node.solve()
        pdb.set_trace()

    return 0
    # if MAX_TIME:
    #     return run_with_timeout()
    # else:
    #     return explore()


def init_project():
    project = Project(
        thing=INSTR_BIN,
        ignore_functions=['printf', '__trace_jump', '__trace_jump_set'])
    entry = project.factory.entry_state(stdin=SimFileStream)
    simgr = project.factory.simulation_manager(entry)
    simgr.use_technique(DFS())
    return simgr

    # symex_paths_gen = my_symex_rec(entry, [entry])
    # symex_paths = [symex_path for symex_path in symex_paths_gen]
    # global SIMPOOL
    # SIMPOOL = Pool(processes=CORE) if (CORE > 1 and not SIMPOOL) else None
    #
    # if SIMPOOL:
    #     conex_paths = SIMPOOL.map(enumerate_path, symex_paths)
    # else:
    #     conex_paths = [enumerate_path(symex_path) for symex_path in symex_paths]
    # return len(conex_paths)


def enumerate_path(symex_path):
    LOGGER.info("Starting to enumerate a path...")
    value = solve_inputs(symex_path[-1])
    conex_result = my_conex(value)
    conex_path, return_code = conex_result

    LOGGER.info("INPUT value: {}; INPUT bytes: {}; RETURN code: {}"
                .format(int.from_bytes(value, 'big', signed=True),
                        value,
                        return_code))
    LOGGER.info("{} {} {}".format("SymEx".rjust(9), "ConEx".ljust(9),
                                  "Constraints"))
    for node in symex_path:
        constraints = node.solver.constraints
        if conex_path and hex(node.addr) == conex_path[0]:
            LOGGER.info(hex(node.addr).rjust(9),
                        conex_path[0].ljust(9),
                        constraints)
            conex_path.pop(0)
        else:
            LOGGER.info("{} {} {}".format(
                hex(node.addr).rjust(9), ''.rjust(9), constraints))
    for addr in conex_path:
        LOGGER.info("ConEx addr not in SymEx:", addr)
    LOGGER.info("\n")
    return conex_path


def symex_step(node):
    try:
        successors = node.step().successors
    except (SimProcedureError, SimMemoryAddressError, SimUnsatError):
        successors = []
    return successors


def my_symex_rec(root, prefix):
    children = symex_step(root)
    if children:
        for child in children:
            for path in my_symex_rec(child, prefix + [child]):
                yield path
    else:
        yield prefix


def solve_inputs(leaf):
    target = leaf.posix.stdin.load(0, leaf.posix.stdin.size)
    value = leaf.solver.eval(target, cast_to=bytes)
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
        program = sp.Popen(INSTR_BIN, stdin=sp.PIPE, stdout=sp.PIPE,
                           stderr=sp.PIPE, close_fds=True)
        try:
            msg = program.communicate(input_bytes, timeout=CONEX_TIMEOUT)
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

    if SAVE_TESTCASES or SAVE_TESTINPUTS:
        time_stamp = time.clock()
        if SAVE_TESTCASES:
            output_msg = report_msg[0].decode('utf-8')
            save_tests_to_file(time_stamp, output_msg)
        if SAVE_TESTINPUTS:
            save_input_to_file(input_bytes, time_stamp)

    return trace, return_code


def save_input_to_file(time_stamp, input_bytes):
    os.system("mkdir -p inputs/{}".format(DIR_NAME))
    with open('inputs/{}/{}'.format(DIR_NAME, time_stamp), 'wb+') as input_file:
        input_file.write(input_bytes)


def save_tests_to_file(time_stamp, data):
    with open('tests/{}/{}.xml'.format(
            DIR_NAME, time_stamp), 'wt+') as input_file:
        input_file.write(
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
        input_file.write(
            '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" '
            '"https://sosy-lab.org/test-format/testcase-1.1.dtd">\n')
        input_file.write('<testcase>\n')
        input_file.write(data)
        input_file.write('</testcase>\n')


# def run_with_timeout() -> int:
#     """
#     A wrapper for run(), break run() when MAX_TIME is reached
#     """
#
#     def raise_timeout(signum, frame):
#         LOGGER.debug("Signum: {};\nFrame: {};".format(signum, frame))
#         LOGGER.info("{} seconds time out!".format(MAX_TIME))
#         raise TimeoutError
#
#     assert MAX_TIME
#     # Register a function to raise a TimeoutError on the signal
#     signal.signal(signal.SIGALRM, raise_timeout)
#     # Schedule the signal to be sent after MAX_TIME
#     signal.alarm(MAX_TIME)
#     try:
#         return explore()
#     except TimeoutError:
#         pass


if __name__ == '__main__':
    sys.setrecursionlimit(1000000)
    parser = argparse.ArgumentParser(description='DFS')
    # parser.add_argument('--sv-comp', action="store_true",
    #                     help='Link __VERIFIER_*() functions, *.i files implies --source')
    parser.add_argument('--save-inputs', action='store_true',
                        help='Save inputs as binary files')
    parser.add_argument('--save-tests', action='store_true',
                        help='Save inputs as TEST-COMP xml files')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='Increase output verbosity')
    parser.add_argument("file",
                        help='Binary or source file')
    parser.add_argument("--random-seed", type=int, default=RAN_SEED,
                        help='The seed for randomness')
    parser.add_argument("--core", type=int, default=1,
                        help='Number of cores available')
    parser.add_argument("--symex-timeout", type=int, default=SYMEX_TIMEOUT,
                        help='The time limit for symbolic execution')
    parser.add_argument("--conex-timeout", type=int, default=CONEX_TIMEOUT,
                        help='The time limit for concrete binary execution')
    parser.add_argument("-o", default=None,
                        help='Binary file output location when input is a C source')
    parser.add_argument("--compile", default="make",
                        help='How to compile C input files')
    parser.add_argument("-64", dest="m64", action="store_true",
                        help='Compile with -m64 (override platform default)')
    parser.add_argument("-32", dest="m32", action="store_true",
                        help='Compile with -m32 (override platform default)')
    parser.add_argument("--cc", default="cc",
                        help='C compiler to use together with --compile svcomp')
    args = parser.parse_args()

    SAVE_TESTINPUTS = args.save_inputs
    SAVE_TESTCASES = args.save_tests
    CORE = args.core
    SYMEX_TIMEOUT = args.symex_timeout
    CONEX_TIMEOUT = args.conex_timeout
    RAN_SEED = args.random_seed
    LOGGER.setLevel(logging.DEBUG if args.verbose else logging.ERROR)

    if RAN_SEED is not None:
        random.seed(RAN_SEED)

    if args.verbose:
        LOGGER.setLevel(logging.DEBUG)

    is_c = args.file[-2:] == '.c'
    is_i = args.file[-2:] == '.i'
    is_source = is_c or is_i

    if is_source:
        source = args.file
        stem = source[:-2]

        if args.m32 and args.m64:
            LOGGER.error("-32 is incompatible with -64")
            sys.exit(2)

        if args.m32:
            verifier_c = "__VERIFIER32.c"
        else:
            verifier_c = "__VERIFIER.c"

        if args.compile == "make":
            if args.o:
                LOGGER.warning("--compile make overrides -o INSTR_BIN")
            INSTR_BIN = stem + ".instr"
            LOGGER.info('Making {}'.format(INSTR_BIN))
            sp.run(["make", "-B", INSTR_BIN])
        elif args.compile == "svcomp":
            if not args.o:
                LOGGER.error("--compile svcomp requires -o INSTR_BIN")
                sys.exit(2)
            INSTR_BIN = args.o
            asm = INSTR_BIN + ".s"
            ins = INSTR_BIN + ".instr.s"
            sp.run([args.cc, "-no-pie", "-o", asm, "-S", source])
            sp.run(["./tracejump.py", asm, ins])
            sp.run([args.cc, "-no-pie", "-O0", "-o", INSTR_BIN, verifier_c,
                    "__VERIFIER_assume.instr.s",
                    "__trace_jump.s",
                    "__trace_buffered.c",
                    ins])
        elif args.compile == "trace-cc":
            if args.o:
                INSTR_BIN = args.o
            else:
                INSTR_BIN = stem
            LOGGER.info('Compiling {} with trace-cc'.format(INSTR_BIN))
            sp.run(["./trace-cc", "-static", "-L.", "-legion", "-o", INSTR_BIN, source])
        else:
            LOGGER.error("Invalid compilation mode: {}".format(args.compile))
            sys.exit(2)

        sp.run(["file", INSTR_BIN])

        UNINSTR_BIN = ".".join(INSTR_BIN.split(".")[:-1])
        sp.run(["file", INSTR_BIN])
        sp.run([args.cc, "-no-pie", "-O0", "-o", UNINSTR_BIN,
                verifier_c, "__VERIFIER_assume.c", source])
    else:
        INSTR_BIN = args.file

    binary_name = INSTR_BIN.split("/")[-1]
    DIR_NAME = "{}_{}_{}_{}".format(binary_name, 1, 0, TIME_START)
    PROGRAM_NAME = args.file.split("/")[-1]
    #
    # if is_source and SAVE_TESTCASES:
    #     os.system("mkdir -p tests/{}".format(DIR_NAME))
    #     with open("tests/{}/metadata.xml".format(DIR_NAME), "wt+") as md:
    #         md.write('<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
    #         md.write(
    #             '<!DOCTYPE test-metadata PUBLIC "+//IDN sosy-lab.org//DTD test-format test-metadata 1.1//EN"
    #             "https://sosy-lab.org/test-format/test-metadata-1.1.dtd">\n')
    #         md.write('<test-metadata>\n')
    #         md.write('<sourcecodelang>C</sourcecodelang>\n')
    #         md.write('<producer>Legion</producer>\n')
    #         md.write(
    #             '<specification>CHECK( LTL(G ! call(__VERIFIER_error())) )</specification>\n')
    #         md.write('<programfile>{}</programfile>\n'.format(args.file))
    #         res = sp.run(["sha256sum", args.file], stdout=sp.PIPE)
    #         out = res.stdout.decode('utf-8')
    #         sha256sum = out[:64]
    #         md.write('<programhash>{}</programhash>\n'.format(sha256sum))
    #         md.write('<entryfunction>main</entryfunction>\n')
    #         md.write('<architecture>32bit</architecture>\n')
    #         md.write('<creationtime>{}</creationtime>\n'.format(
    #             datetime.datetime.now()))
    #         md.write('</test-metadata>\n')

    print(main())
