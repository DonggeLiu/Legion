# Legion

A concolic (concrete-symbolic) execution tool assisted by the Monte Carlo tree search algorithm.

Concolic (concrete-symbolic) testing is a natural combination to balance the complementary nature of fuzzing and symbolic execution and aim for the best of both worlds: 
   * Fuzzing generates concrete inputs at a low cost, but cannot guarantee the coverage of deep execution paths; 
   * Conversely, symbolic execution can compute inputs for all paths, despite being expensive and unscalable due to the path explosion problem.

## Challenge to solve
During the recent years, a main open challenge that have ben studied in coverage-based concolic execution is an efficient program exploration strategy to determine when and where to apply which technique.
  
## Contribution
### Main contribution
  *Legion* formulates this challenge as a problem of sequential decision-making under uncertainty for the first time. It generalises conconlic execution strategies to the exploration-exploitation problem in machine learning and leverages the *Monte Carlo tree search (MCTS)* - a popular framework from AI literature to solve such problem by marrying search \& planning and statistical estimation. Specifically, through iterations of decision sequences, Legion resolves the trade-off between fuzzing and symbolic execution by balancing the considerations of program structure estimation and program exploration planning. This best-first strategy of MCTS provides a principled approach to determine which constraints to flip in pre-existing concolic testing systems.

### Second contribution
  Also, it proposes an *approximate path preserving fuzzing (APPFuzzing)* technique as an alternative to the widely used *American Fuzzing Lop (AFL)* to estimate program structure.

### Third contribution
Moreover, while most existing fuzzing frameworks are designed for specific metrics, Legion adopts a modularised score function to avoid suffering from degraded performance on other metrics of interests.


## Collaborators

### Designers & Developers 

[Dongge Liu](https://github.com/Alan32Liu)

[Gidon Ernst](https://github.com/gernst)

[Toby Murray](https://github.com/tobycmurray)

[Benjamin Rubinstein](https://github.com/brubinstein)

<!--
## TODO

### Version control

1. [x] Independent repository
2. [x] An online doc

### Runner Optimisation

1. [x] Test `tracejump`
2. [x] Replace `QEMU` with `tracejump`
3. [x] `tracejump` optimisation:
    * [x] Investigate the difference between `tracejump` instrumentation and SIMGR

### Tracer optimisation

1. [x] Check into `constraints()` to see how constraints are collected
2. [x] In expansion stage, run `tracer` starting from the node selected in tree policy, instead of from the root.
    * [x] Call `step()` on states:
        * Cannot tell which successor to choose
    * [x] `simgr.explore()`:
        * Cannot use it together with tracer
    * [x] `simgr.run()`:
        * Runs into a dead-end state
        * Uses `step()` internally
    * [x] Fixed the logic to choose successors
3. [ ] ~~Run on pre-instrumentation binary~~

### Program Under Test

1. [x] Program with loops:
    * [x] Why constraints are missing?:
        * Cause repeated bytes recorded by `tracejump` are not recorded by SIMGR
    * [x] match the bytes recorded by `tracejump` with the ones in SIMGR
2. [ ] CGC programs
3. [ ] LAVA-M programs
4. [x] Four-byte-word sample PUT
5. [x] Replace `QEMU` with `tracejump`

### Solver optimisation

1. [x] Quick Sampler
2. [ ] ~~Keep $\delta$ instead of constraints?~~

### Experiments

1. [x] Compare time: Legion - `tracejump` ?= random - `tracejump`:
    * [x] Legion is way more slower on one-byte-input
    * [x] Test on inputs with more bytes (choke-point)
2. [x] simpler loop:
    * [x] `simple_while.c`:
    * [x] check assembly, make sure loops are not simplified away
    * [x] `for` loops

## Progress

1. [x] study `tracejump`
2. [x] fix bugs in `tracejump`
3. [x] sample PUT triggers the difference between `tracejump` & SIMGR:
    * [x] If any:
        * caused by repeated bytes that are not recorded by SIMGR
    * [x] load the assembly or the binary in GDB, scan step through it.
    * [x] Fixing the mismatch

## Next
1. [x] Correct the names in Pie Chart
2. [x] Correct the counters in the algorithm
3. [x] Test on inputs with more bytes
4. [x] Test on inputs with `for` loops
5. ~~Optimisation: avoid executing the binary on inputs that showed up before~~
6. [x] Fixing the mismatch between instrumentation and tracer
7. [x] Mark a node as exhausted if quick sampler cannot find any new in_str from it
8. [x] A automatic program to compare the performance between legion and given benchmark
9. [x] Fix back-propagation: assign rewards according to the in_str generated
10. [x] Version-control Angr

## Important notes:
1. Cannot keep symbolic execution states with preconstraints in the MCTS tree node, otherwise, future symbolic execution will be limited to this input.
2. Four kinds of nodes:
    1. White:  In TraceJump     + Not sure if in Angr   + check Symbolic state later    + may have simulation child
    2. Red:    In TraceJump     + Confirmed in Angr     + has Symbolic state            + has Simulation child
    3. Black:  In TraceJump     + Confirmed not in Angr + No Symbolic state             + No Simulation child
    4. Gold:   Not in TraceJump + Not in Angr           + Same Symbolic state as parent + is a Simulation child
    5. Purple: Unknown TJ path  + SymEx found in Angr   + has Symbolic state            + is a Phantom Node
3. Installation order: `Angr` -> `Cle` -> `Claripy`


## Changes to dependencies
1. Angr: Fixed the loggers of angr, so that it will not affect importers
2. Claripy: 
    * Added a new approximate constraint solver backend: Quick Sampler
    * An assertion on the length of `exprs`
-->
