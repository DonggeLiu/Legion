#!/usr/bin/env python3

import os
import pdb
import subprocess as sp


expectations = {
    'test_for.c':       6,
    'test_if.c':        2,
    'test_dowhile.c':   9,
    'test_while.c':     9,
    'test_switch.c':    4,
    'test_N.c':         3,
}


for test in os.listdir("./TraceJumpTests/"):
    if test[-2:] != ".c":
        continue
    print("Testing {}:".format(test), end=" ")
    output = sp.run(
        args=["./Legion.py", "./Test/TraceJumpTests/{}".format(test)],
        cwd="../",
        stdout=sp.PIPE
    ).stdout
    paths = output.decode("utf-8").split("\n")[-2]
    try:
        assert int(paths) == expectations[test]
    except AssertionError:
        print("Failed, expected {}, found {} ".format(expectations[test], paths))
    else:
        print("Succeeded.")
