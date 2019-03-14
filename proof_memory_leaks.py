import gc
import os

import angr

PID = os.getpid()
BINARY = "sample.instr"

print("{}: At the beginning".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

PROJ = angr.Project(BINARY)
print("{}: Created PROJ".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

del PROJ
print("{}: Deleted PROJ".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

gc.collect()

print("{}: Collected GC".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

PROJ = angr.Project(BINARY)
print("{}: Created PROJ".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

prev_state = PROJ.factory.entry_state(stdin=angr.storage.file.SimFileStream)
print("{}: Computed entry state".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

for _ in range(3):
    next_state = prev_state.step().successors[0]
    print("{}: After symbolic execution".format(
        os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

    del prev_state
    print("{}: Deleted previous state".format(
        os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

    gc.collect()
    print("{}: Collected GC".format(
        os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))
    prev_state = next_state

print("{}: Last state recycled".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

gc.collect()
print("{}: Collected GC".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

del prev_state
print("{}: All states recycled".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

gc.collect()
print("{}: Collected GC".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

del PROJ
print("{}: Deleted PROJ".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))

gc.collect()
print("{}: Collected GC".format(
    os.popen("more /proc/{}/statm".format(PID)).read().split(" ")))
