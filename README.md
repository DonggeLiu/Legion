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

## How to run

### Dependencies

Legion relies on Approximate-path-preserving fuzzing, which is implemented within the following two `pip3` pacakges:

[Our fork of angr](https://github.com/Alan32Liu/angr)

[Our fork of claripy](https://github.com/Alan32Liu/claripy)


### Command

```shell
python3 Legion.py <program_under_test.c>
````

#### Hyper-parameters & Optional flags

1. Tree depth, e.g. `--tree-depth-limit 100`;
2. Exploration factor (rho), e.g. `--rho 0.0025`;
3. Number of cores, e.g. `--core 1`;
4. Symbolic execution timeout (in seconds, 0 means no limitation), e.g. `--symex-timeout 0`;
5. Concrete execution timeout (in seconds, 0 means no limitation), e.g. `--conex-timeout 0`;
6. Minimum number of simulations in each iteration, e.g. `--min-samples`;
6. Keep running after finding bugs, `--coverage-only`;
7. Keep running after the tree is fully explored (in case of symbolic execution error, such as eager concretisation), e.g. `--persistent`;
8. Score function, e.g. `--score=uct`


## Collaborators

### Designers & Developers 

[Dongge Liu](https://github.com/Alan32Liu)

[Gidon Ernst](https://github.com/gernst)

[Toby Murray](https://github.com/tobycmurray)

[Benjamin Rubinstein](https://github.com/brubinstein)

