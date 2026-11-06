# Tier 1 is slow and partly opaque
> Summary: Tier-1 tests should be fast, readable and deterministic in what they check: cut the slow tail, replace pinned generator seeds with minimal hand-written reproducers (or delete them), and take the easy wins (shared setup, cheaper debug checks). Deleting and consolidating tests is in scope.
> Tags: tests

Goal: most tests in milliseconds, none over about a second, each one's scenario readable from its body. **Deleting tests that add little, are redundant with others, or test a seed rather than a rule is fully valid, as is merging near-duplicates.** A test earns its tier-1 cost by catching something no cheaper test catches (notes/testing.md "What finds bugs": tier 1 found about 2 of about 300 bugs).

## Measured (osis-node `it`, dev profile, 8 threads, `order::` skipped)
- 983 tests, 386 test-s. Median 100 ms, p90 0.64 s, p99 5.2 s, max 18.8 s; 50 under 10 ms.
- 72 tests at 1 s or more take 63% of the time (243 s); the 666 under 0.2 s take 12%. Slowest: `hostile_host::linked_header_prefix_checked_spec_commits_4` 18.8 s, `hostile_host::header_list_chunks_level_2_only_spec_wire_5` 13.7, `shred_sync::purged_synced_body_crash_safe_spec_commits_5` 12.6, `shred_sync::purge_carrier_through_hosts_spec_crdt_4_7` 10.9, `validity::unmerge_paged_*` about 10 each, `fill::*_part_way_loses_nothing` 7-9.
- Whole-binary CPU (cpuprof, `order::` included): crypto 33% inclusive (dependencies already at opt-level 2; half of it the forensic attack and signature checks), `order::check_orders` 20%, `check_rebuilt` 13%, cbor 10%, allocation 20%. Toy crypto would gain at most about 1.5x: not the lever.
- A median test is a whole in-memory network (nodes and a host, a group, signed encrypted commits in a real store, sync until settled): sync settling about 55-60%, group and peer setup (`Net::group_seeded`, `Net::pair`) 20-30%, apply about 20%.
- Other crates not measured.

## Work
1. **Slow tail.** For each tier-1 test over about 1 s (all crates; `RUSTC_BOOTSTRAP=1 <binary> -Z unstable-options --report-time`, notes/testing.md): shrink it to its point, merge it into a sibling, move it to tier 2, or delete it.
2. **Pinned generator seeds** (about 115 tier-1 tests run a random scenario generator at fixed seeds, e.g. `osis-engine` `rotation::tests::withheld_*`, 750 ms each). A seed's scenario drifts with every change to the generator or engine and nothing notices: `withheld_regrant_by_unaware_admin_spec_crypto_4` seed 9490147 no longer reaches the excused path its comment describes (282407 and 9490002 still do). Replace each with a minimal hand-written scenario of the bug it was pinned for (the steps in the test body, asserting the rule), or delete it where the rule is already covered. The generators stay as tier-2 explorers. The `withheld_departures` oracle's excuses (`invalid_raise`, `regranted`, `sharers`) each want a spec sentence or removal. Hand-made seed tests already exist in osis-node `pinned::`; issues/seed-pinned-bugs-without-test.md is one still missing.
3. **Easy wins.**
   - Shared fixtures: build the common starting network (group, peers, grants) once and clone it per test instead of every test signing and syncing it from scratch.
   - Test rules below the network: validity, retention and permission rules against the engine or perm layer directly; a full `Net` only where sync is the point.
   - `check_rebuilt` (13%): sample it more sparsely in tier 1, or keep it full only in tests of apply and validity, if that does not lose what it catches (it found bugs; measure before cutting).
   - The forensic attack (17% of node CPU, mostly trial decrypts): one smaller instance in tier 1, the full one in tier 2.
   - `order::` (20%): fewer random orders per held set where the exhaustive and fixed orders already cover it.
   - The debug re-decode on every `secrets_in` cache hit (22% of `osis` `it`, notes/testing.md): move it into `Engine::recheck`.
