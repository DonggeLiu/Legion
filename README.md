# Principes

Second version of Legion, with progresses and TODOs

## TODOs

### Version control

1. [x] Independent repository
2. [x] An online doc

### Runner Optimisation

1. [x] Replace `QEMU` with `tracejump`
2. [ ] `tracejump` optimisation

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

### Program Under Test

1. [ ] Program with loops:
    * [ ] Why constraints are missing?
2. [ ] CGC programs
3. [ ] LAVA-M programs
4. [ ] Four-byte-word sample PUT

### Solver optimisation

1. [x] Quick Sampler
2. [ ] Keep $\delta$ instead of constraints?

### Experiments

1. [ ] Compare time: Legion - `tracejump` ?= random - `tracejump`
2. [ ] simpler loop:
    * [ ] check assembly, make sure loops are not simplified away

## Progress

1. [x] study `tracejump`
2. [x] fix bugs in `tracejump`
3. [x] sample PUT triggers the difference between `tracejump` & SIMGR:
    * [ ] If any
    * [ ] load the assembly or the binary in GDB, scan step through it.

## Next
