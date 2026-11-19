# m2-paths-review
- A roles-model control batch prints a shrunk world per failing property, and the shrink is single-core: a batch of controls under `tools/heavy` can hold the lock on one core. Counted the controls with a throwaway test calling `random`/`family_run` without `print` instead; a `--no-shrink` mode would do.
- `family_run(stride)` with a stride sharing a factor with the first dimension's size silently fixes that dimension (every 50th world: `h_t1` always false). Strides of mixed-radix families must be coprime with every radix.
