import logging
import random
import struct
import subprocess
import sys
import time

MAX_PATHS = 18
NUM_SAMPLES = 1
DSC_PATHS = set()
PST_INSTRS = set()
MAX_ROUNDS = float('inf')
CUR_ROUND = 0
SIMUL_TIME = 0.
TIME_LOG = {}

BINARY = sys.argv[1]
SEED = ''.join(sys.argv[2:])
print(SEED)
LOGGER = logging.getLogger('rd')
LOGGER.setLevel(logging.ERROR)
LOGGER.addHandler(logging.StreamHandler(sys.stdout))


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


def generate_random(seed):

    new_bytes = bytes([random.randint(0, 255) for _ in seed])
    return new_bytes


def program(in_str):
    return tuple(traced_with_input(in_str))


def unpack(output):
    assert(len(output) % 8 == 0)

    addrs = []
    for i in range(int(len(output) / 8)):
        addr = struct.unpack_from('q', output, i * 8)
        addrs.append(addr[0])
    return addrs


def traced_with_input(in_str):
    p = subprocess.Popen(BINARY, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, error) = p.communicate(in_str)
    addrs = unpack(error)

    return addrs


def cannot_terminate():
    # LOGGER.debug("=== Iter:{} === len(DSC_PATHS):{}".format(CUR_ROUND, len(DSC_PATHS)))
    print('{},{}'.format(CUR_ROUND, len(DSC_PATHS)))
    return len(DSC_PATHS) < MAX_PATHS and CUR_ROUND < MAX_ROUNDS


@timer
def run():
    global CUR_ROUND, SIMUL_TIME

    history = []

    while cannot_terminate():
        CUR_ROUND += 1
        new_in = generate_random(SEED)
        # while new_in in PST_INSTRS:
        #     new_in = generate_random(SEED)
        simul_start = time.time()
        path = program(new_in)
        PST_INSTRS.add(new_in)
        simul_end = time.time()
        SIMUL_TIME += simul_end - simul_start
        DSC_PATHS.add(path)
        history.append([CUR_ROUND, len(DSC_PATHS)])
        if CUR_ROUND >= MAX_ROUNDS:
            break
    return history


if __name__ == "__main__" and len(sys.argv) > 1:

    results = run()
    print(TIME_LOG)
    print(SIMUL_TIME)
    print(CUR_ROUND)
