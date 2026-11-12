# Merges made on partial views fork again
> Summary: Forks held alike take one merge per role (`concurrent_removals_take_one_merge_spec_crypto_4`), but a node decides as soon as it holds two forks: nodes holding different subsets each read as the merger (`fork_merger`), their merges fork again, and so on while views differ. In osis `sync::redeem_held_joins_nothing` (four rotators, all online) the grant ending takes 3 finalizes and 5 merges where 1 per role would do, and the link key's earlier concurrent rotations about 18 rotations of the group; the test costs 34 G instructions.
> Priority: low
> Tags: keys, performance, tests

## Measured
Probe (not kept) printing each rotation commit and `rotation_due` reason in that test.
- Grant end: three writers finalize at once, each with its rotation (three forks of read and of write, all covering). Carol holding {alice's, hers} and Bob holding {alice's, his} each read as merger and merge concurrently; then each again on the next fork (Bob write, Carol read+write, Bob write). Carol's read merge also rotates write (`shown_roles`: her write runs through the link key, shown only by a proof in a write keyset), which forks write against Bob's write merge.
- Before it: two nodes rotate the link key K at once (its departure), each cascading to the group (`rotate_above`); K's merges make the group's boxes to K stale at every rotator (`blocked`, no departure), so the group forks and merges round after round while K's anchors fork and Seal waits at some.

## Question
No rule over the forks a node holds is independent of which it holds. Tried: the merger as the maker of the newest current epoch (including the newest) instead of the newest other than the newest: 3 merges after the grant end instead of 5, but more before it (28 rotations instead of 18; a node whose own fork sits at a higher n merges on every older fork it meets), and it changes `rotation_after_invalid_one_through_regrants_spec_crypto_4`'s shape. Options: decide a fork-only merge (every current epoch covering) only at the end of a complete pass, as re-seals and history adds do; or merge only where a fork matters (a holder actor whose anchors fork, Seal), since `merge_due` already handles a fork missing a departure.
