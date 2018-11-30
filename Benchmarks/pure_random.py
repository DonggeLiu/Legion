import logging
import sys
import struct
import random
import time

import subprocess32

MAX_PATHS = 9
NUM_SAMPLES = 1
DSC_PATHS = set()
MAX_ROUNDS = float('inf')
CUR_ROUND = 0
SIMUL_TIME = 0.

BINARY = sys.argv[1]
SEED = ''.join(sys.argv[2:])

LOGGER = logging.getLogger('rd')
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(logging.StreamHandler(sys.stdout))


def generate_random(seed):
    in_str = "".join(map(chr, [random.randint(0, 255) for _ in seed]))
    return in_str


def program(in_str):
    return tuple(traced_with_input(in_str))


def unpack(output):
    assert(len(output) % 8 == 0)

    addrs = []
    for i in xrange(len(output) / 8):
        addr = struct.unpack_from('q', output, i * 8)
        addrs.append(addr[0])
    return addrs


def traced_with_input(in_str):

    p = subprocess32.Popen(BINARY, stdin=subprocess32.PIPE, stderr=subprocess32.PIPE)
    (output, error) = p.communicate(in_str)
    addrs = unpack(error)

    return addrs


def cannot_terminate():
    LOGGER.debug("=== Iter:{} === len(DSC_PATHS):{}"
                 .format(CUR_ROUND, len(DSC_PATHS)))
    return len(DSC_PATHS) < MAX_PATHS and CUR_ROUND < MAX_ROUNDS


def run():
    global CUR_ROUND, SIMUL_TIME

    history = []

    while cannot_terminate():
        CUR_ROUND += 1
        new_in = generate_random(SEED)
        simul_start = time.time()
        path = program(new_in)
        simul_end = time.time()
        SIMUL_TIME += simul_end - simul_start
        # prev_num = len(DSC_PATHS)
        DSC_PATHS.add(path)
        # if len(DSC_PATHS) > prev_num:
        #     LOGGER.info(map(hex, path))
        history.append([CUR_ROUND, len(DSC_PATHS)])
        if CUR_ROUND >= MAX_ROUNDS:
            break
    return history


if __name__ == "__main__" and len(sys.argv) > 1:

    start = time.time()
    results = run()
    end = time.time()
    print end - start
    print SIMUL_TIME
    print CUR_ROUND