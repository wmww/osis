# Concurrent merges of an account's heads fork again without bound
> Summary: Two nodes of P merging the same heads at once mint two epochs (each merge carries its maker's random seed, takes, answers and list), which fork again; under lockstep delivery the rounds never end, in the engine and in roles-model `forks`. Design: notes/account-forks-design.md (Merges: a merge's epoch is a pure function of the plain tips it joins).
> Priority: critical
> Tags: perm, engine, security

## What happens
- spec/permissions.md §5.5 states it as a limit: rotations two nodes of P make at once fork again, and nothing bounds the rounds while nodes merge within one sync of each other. Measured by hand in `rotation::tests_signing::merge_rounds_after_concurrent_rotations`; lockstep forks every round, and `forks` storms the same way when A and B act on the same receipts.
- Rejected answers (notes/engine-validity-epochs.md, the merge limit under Sides on the fork-sides branch): a deterministic merger designates a device; deferring to a held superset merge stalls on its maker; treating merges of the same heads as one by parents fails for a removed node's fork with the removal's parents (the design keys a merge by its plain tips and derives its seed from theirs, so only holders of every tip's seed can make it).

## Fix
notes/account-forks-design.md: merges carry nothing but the join; a merge's seed and epoch name are a function of its tips; plain rotations carry everything else, at most once per node per event. Model first (the `custody` module, lockstep schedule, `merge-random` control).
