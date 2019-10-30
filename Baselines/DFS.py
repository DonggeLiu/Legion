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
from typing import List

from angr import Project
from angr.errors import SimProcedureError, SimMemoryAddressError, SimUnsatError
from angr.storage.file import SimFileStream

BINARY = None
SAVE_TESTCASES = False
SAVE_TESTINPUTS = False
TIME_START = time.time()
MAX_TIME = 0

# Logging
LOGGER = logging.getLogger("Legion")
LOGGER.setLevel(logging.ERROR)
sthl = logging.StreamHandler()
sthl.setFormatter(fmt=logging.Formatter('%(message)s'))
LOGGER.addHandler(sthl)
logging.getLogger('angr').setLevel('ERROR')


def explore():
    project = Project(thing=BINARY, ignore_functions=['printf', '__stack_chk_fail'])
    entry = project.factory.entry_state(stdin=SimFileStream)
    symex_paths_gen = my_symex_rec(entry, [entry])

    path_count = 0
    while True:
        try:
            symex_path = next(symex_paths_gen)
        except StopIteration:
            break
        path_count += 1
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
    return path_count


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

    if SAVE_TESTCASES or SAVE_TESTINPUTS:
        time_stamp = time.clock()
        if SAVE_TESTCASES:
            output_msg = report_msg[0].decode('utf-8')
            save_tests_to_file(time_stamp, output_msg)
        if SAVE_TESTINPUTS:
            save_input_to_file(input_bytes, time_stamp)

    return [hex(addr) for addr in trace], return_code


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
            '<!DOCTYPE testcase PUBLIC "+//IDN sosy-lab.org//DTD test-format testcase 1.1//EN" "https://sosy-lab.org/test-format/testcase-1.1.dtd">\n')
        input_file.write('<testcase>\n')
        input_file.write(data)
        input_file.write('</testcase>\n')


def run_with_timeout() -> int:
    """
    A wrapper for run(), break run() when MAX_TIME is reached
    """

    def raise_timeout(signum, frame):
        LOGGER.debug("Signum: {};\nFrame: {};".format(signum, frame))
        LOGGER.info("{} seconds time out!".format(MAX_TIME))
        raise TimeoutError

    assert MAX_TIME
    # Register a function to raise a TimeoutError on the signal
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after MAX_TIME
    signal.alarm(MAX_TIME)
    try:
        return explore()
    except TimeoutError:
        pass


def main() -> int:
    """
    MAX_TIME == 0: Unlimited time budget
    MAX_TIME >  0: Time budget is MAX_TIME
    """
    if MAX_TIME:
        return run_with_timeout()
    else:
        return explore()


if __name__ == '__main__':
    sys.setrecursionlimit(1000000)
    parser = argparse.ArgumentParser(description='Legion')
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
    args = parser.parse_args()

    SAVE_TESTINPUTS = args.save_inputs
    SAVE_TESTCASES = args.save_tests
    LOGGER.setLevel(logging.DEBUG if args.verbose else logging.ERROR)

    is_source = args.file[-2:] in ['.c', '.i']
    if is_source:
        source = args.file
        BINARY = source[:-2]
        LOGGER.info('Building {}'.format(BINARY))
        os.system("gcc -ggdb -o {} {} __VERIFIER.c".format(BINARY, source))
    else:
        BINARY = args.file

    binary_name = BINARY.split("/")[-1]
    DIR_NAME = "{}_{}".format(binary_name, TIME_START)
    if is_source and SAVE_TESTCASES:
        os.system("mkdir -p tests/{}".format(DIR_NAME))
        with open("tests/{}/metadata.xml".format(DIR_NAME), "wt+") as md:
            md.write('<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
            md.write(
                '<!DOCTYPE test-metadata PUBLIC "+//IDN sosy-lab.org//DTD test-format test-metadata 1.1//EN" "https://sosy-lab.org/test-format/test-metadata-1.1.dtd">\n')
            md.write('<test-metadata>\n')
            md.write('<sourcecodelang>C</sourcecodelang>\n')
            md.write('<producer>Legion</producer>\n')
            md.write(
                '<specification>CHECK( LTL(G ! call(__VERIFIER_error())) )</specification>\n')
            md.write('<programfile>{}</programfile>\n'.format(args.file))
            res = sp.run(["sha256sum", args.file], stdout=sp.PIPE)
            out = res.stdout.decode('utf-8')
            sha256sum = out[:64]
            md.write('<programhash>{}</programhash>\n'.format(sha256sum))
            md.write('<entryfunction>main</entryfunction>\n')
            md.write('<architecture>32bit</architecture>\n')
            md.write('<creationtime>{}</creationtime>\n'.format(
                datetime.datetime.now()))
            md.write('</test-metadata>\n')

    print(main())
