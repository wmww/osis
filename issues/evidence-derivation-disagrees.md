# The evidence derivation disagrees with the model since the stub rewrite
> Summary: osis-engine `evidence::the_derivation_agrees_with_the_model_{plain,large}` fail on main: in story worlds (units 5) and random ones, a sync ID's derived required set lacks items the model's has; cause not sorted.
> Priority: normal
> Tags: engine, tests

Observed at baebb90c8 (the stub rewrite on main), plain: "story units 5: 10 disagreements, first: step 33 node 0 sid 11: model {(0, 10), (1, 10), (2, 10), (5, 10), (15, 13), (16, 13), (32, 10)} derivation {(0, 10), (1, 10), (2, 10), (5, 10), (32, 10)}"; large: 20 worlds disagree, each the derivation missing items the model requires. The model's required set is a sync ID's bodies plus its chain stubs' role entries (core/test/held-model/README.md); the derivation (notes/evidence-derivation.md) may not yet count chain stubs, or the test's world builder may not log them. First step: which items the derivation misses (their kind and the stub they belong to).
