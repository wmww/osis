# A read rotation after a removal drops the removal's keys.0 part
> Summary: engine `rotation::tests_carried::own_demotion_keyset_held_by_a_node_joining_after_compaction_plain_spec_crypto_4` fails on every seed that rotates read again after B removes W from X1 (its first draw 0): B drops the removal's `keys.0` part while its keysets are current, and a newcomer fed what B holds then lacks the removal's Sync keyset B holds. The default seeds 0..4 never took that branch; unstudied whether the product or the test's expectation is wrong.
> Priority: normal
> Tags: engine, tests

**Seen**: seeds 7-12 (any seed whose first `rng.next(2)` is 0) fail at main; 0-6 pass. Replay: `OSIS_OWN_DEMOTION_START=7 OSIS_OWN_DEMOTION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_carried::own_demotion_keyset_held_by_a_node_joining_after_compaction_plain_spec_crypto_4`. KNOWN in tools/known_failures.txt.

- The test: B removes W from X1 (its own rotation, keysets with `demotes`), then on that branch rotates read alone (`rotate_now(.., {Read})`), snapshots `keys.0` (and perhaps `secrets.0`), passes `ROLE_KEEP` and drops what the snapshot covers. Its first assert (`body_not_dropped(rm, x1, keys.0)`) fails; with it tolerated, the next (the newcomer holds each `demotes` keyset B holds) fails on the Sync keyset.
- Questions: does a read-alone rotation rotate sync too, or re-write the other roles' keysets (so the removal's part is no longer the only carrier of a current keyset)? If the removal's Sync keyset is no longer current, the newcomer need not hold it and the test should compare current keysets only; if the write keyset is still current only in the removal's part, its drop is the bug (spec/crypto.md §4 Held keyset; spec/commits.md §5 Keep bounds).
