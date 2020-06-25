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

