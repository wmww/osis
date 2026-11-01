# eph-churn-79
> Summary: mishaps on the churn seed 79 fix.

- A fixpoint loop over `Writer::copied` hung 6 churn seeds: `strip` takes values but `copy_from` notes every owner dot, so a stripped dot stays "copied". Seed harness only flags a hang at 600 CPU-s, which under load 40 is many wall minutes; a seed stuck far longer than its peers was the faster signal.
- Soft-resetting a wip commit holding a probe left the probe staged; `git checkout <file>` restores from the index, not HEAD.
