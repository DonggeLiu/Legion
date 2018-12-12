# Principes

Second version of Legion, with progresses and TODOs

## TODO

### Version control

1. [x] Independent repository
2. [x] An online doc

### Runner Optimisation

1. [x] Test `tracejump`
2. [x] Replace `QEMU` with `tracejump`
3. [ ] `tracejump` optimisation:
    * [ ] Investigate the difference between `tracejump` instrumentation and SIMGR

### Tracer optimisation

1. [ ] Check into `constraints()` to see how constraints are collected
2. [ ] In expansion stage, run `tracer` starting from the node selected in tree policy, instead of from the root.
    * [x] Call `step()` on states:
        * Cannot tell which successor to choose
    * [x] `simgr.explore()`:
        * Cannot use it together with tracer
    * [x] `simgr.run()`:
        * Runs into a dead-end state
        * Uses `step()` internally
    * [ ] Alternatives?
3. [ ] Run on pre-instrumentation binary

### Program Under Test

1. [ ] Program with loops:
    * [x] Why constraints are missing?:
        * Cause repeated bytes recorded by `tracejump` are not recorded by SIMGR
    * [ ] match the bytes recorded by `tracejump` with the ones in SIMGR
2. [ ] CGC programs
3. [ ] LAVA-M programs
4. [ ] Four-byte-word sample PUT
5. [x] Replace `QEMU` with `tracejump`

### Solver optimisation

1. [x] Quick Sampler
2. [ ] Keep $\delta$ instead of constraints?

### Experiments

1. [ ] Compare time: Legion - `tracejump` ?= random - `tracejump`:
    * [x] Legion is way more slower on one-byte-input
    * [ ] Test on inputs with more bytes (choke-point)
2. [ ] simpler loop:
    * [x] `simple_while.c`:
    * [x] check assembly, make sure loops are not simplified away
    * [ ] `for` loops

## Progress

1. [x] study `tracejump`
2. [x] fix bugs in `tracejump`
3. [x] sample PUT triggers the difference between `tracejump` & SIMGR:
    * [x] If any:
        * caused by repeated bytes that are not recorded by SIMGR
    * [x] load the assembly or the binary in GDB, scan step through it.
    * [ ] Fixing the mismatch

## Next
1. [x] Correct the names in Pie Chart
2. [x] Correct the counters in the algorithm
3. [ ] Test on inputs with more bytes
4. [ ] Test on inputs with `for` loops
5. [ ] Optimisation: avoid executing the binary on inputs that showed up before
6. [x] Fixing the mismatch between instrumentation and tracer
7. [ ] Mark a node as exhausted if quick sampler cannot find any new in_str from it
8. [ ] A automatic program to compare the performance between legion and given benchmark
9. [ ] Fix back-propagation: assign rewards according to the in_str generated
10. [x] Version-control Angr

## Important notes:
1. Cannot keep symbolic execution states with preconstraints in the MCTS tree node, otherwise, future symbolic execution will be limited to this input.
