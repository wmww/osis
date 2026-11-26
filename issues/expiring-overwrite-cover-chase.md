# An expiring write outlasted by another expiring one is owed covers for ever
> Summary: under purge on replace, an expiring delta overwritten by a write expiring later is replaced (spec/crdt.md §4.8), but no snapshot can cover it (a lasting cover carries no expiring write; an expiring snapshot covers no delta), so every judgment owes a new cover: 149 covers, then sync between writers never ends.
> Priority: critical
> Tags: engine, held-model

- Repro (engine, setting.rs harness): `setup()`, `set(&mut lp, 2, d, &setting(&[(A, History::PurgeOnReplace)]))`, sync; peer 1 puts "one", sync; peer 1 sets A expiring in 1 h, sync, advance 1 s; peer 1 sets A expiring in 2 h, sync. Peer 1 holds 149 snapshots of A and the first expiring body; a following write and `sync_all` does not return.
- Not from the lifetime rule: the first expiring write is outlasted, so it is dead either way; the shape predates it. held-model's `spec_commits::a_write_beaten_only_by_a_shorter_one_lives_spec_crdt_4_8` asserts it replaced (its control) without settling it.
- Options: an expiring snapshot ending no earlier covers an expiring delta it supersedes (the writer's cover is then `write_expiring`'s, ending with the superseder); or a body is owed a cover only when a cover could carry what replaced it (an expiring delta goes by its expiry). Needs spec/commits.md §5 (Covered, Purge on replace) and the model alike, with a held-model test of this shape settling.
