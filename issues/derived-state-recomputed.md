# Derived state is recomputed on every change, by hand-wired caches
> Summary: Everything the engine and node-sync derive (epochs, labels, validity, blocked roles, body keeps) sits behind about thirty hand-keyed caches whose invalidation is all-or-nothing (`Core::generation`, `role_changed`), so any change rebuilds nearly all of it at the next pass, and the most-read derivation (epochs) has no cache. osis `sources::world_waiting` costs about 2.4 G instructions against a floor near 0.1 G. Plan: one memo mechanism that records what it read, replacing the caches.
> Priority: normal
> Tags: engine, node, performance, tests

## What is wrong
The engine's facts are its held commits, the journaled indexes (`Core::ix`), the states, the seeds and the clock; everything else is a function of them. The code computes those functions when asked, and each one found slow got its own cache: a key picked by hand (`generation`, `role_generation`, change counts, `ViewKey`), invalidation calls at the write sites (`Core::wrote` matching aspect names, `role_changed` from about twenty sites, `touch`, the list in `rollback_to`), and a debug comparison with a fresh read because hand-wired invalidation cannot be trusted. Consequences:

1. **All-or-nothing invalidation.** `generation` moves on every changing transaction and `role_changed` on every held-set change, so the caches help only while nothing happens. After any change the next pass rebuilds: a label pass costs 20-30 M instructions whatever changed (36 label passes are half of the setup below), `Engine::ensure_rotated` reruns on 26 of 36 asks, `labels()` and head keys about once per pass.
2. **No cache where the inputs could not be named.** `Core::epochs` (about 5000 calls, each a walk up the record chain with `ActorEpochs::derived` KDFs, `own_epochs`, `base_derived`) and commit validity (`Judge::valid_on`, which checks possession proofs again each time: 150 `Shown::verifies` for a handful of proofs).
3. **Debug builds pay to police the caches**: about a third of the setup below (`apply::check_rebuilt` after every changing transaction 17%; `Engine::recheck` comparisons the rest).

Not redundant, by count: commit header signatures, stamps and serving proofs are checked once per receiver.

## Measured
osis `it` `sources::known_stays_here_and_unknown_goes_to_the_node` (almost all `world_waiting` setup: 3 nodes, one group, one client grant, 27 signed commits), debug profile: about 2.4 G instructions (run to run 2.35-2.39; thread timing moves the pass count). The work the setup needs (27 commit signatures, the stamps, seals and key exchanges, each checked once per receiver) is 150-300 curve operations, 70-130 M instructions. Where the rest goes, inclusive: `SyncEngine::handle` about 70% (label passes: `body_sends` with `must_hold` and `body_keeps`, `usable_keys` with `ensure_rotated` and `blocked_roles_of`, `certificates`, `reseal`); inbound entries 15%; the test thread's own API calls about 25%.

## Design
One rule per kind of derived value (notes/coordination.md, Fast by construction):

- **A function of something immutable** is computed where the input enters and kept beside it for as long as the input lives; nothing invalidates it. Built: stored commit records and their parts (`engine/decoded.rs`), an account's role epochs (`AccountView::role_epochs`).
- **A function of mutable facts** is a memo that records what it read, the rule kit's graph follows (notes/fast-design.md §3: a value depends on exactly what it read and has no other way to read). Every index write already goes through four journaled containers (`engine/journal.rs`: `JMap`, `JSet`, `JSetMap`, `JNested`), state writes through `Core::wrote`, record writes through `Tx::put_commit`: change stamps belong in those places, per key for point reads and per table for scans. A memo asked again compares the stamps of what it read; an equal result stops what depends on it. No hand-written key, no invalidation call, one debug comparison inside the memo type.
- **A function of time** states until when its answer holds (as `SyncEngine::rotations` and `labels()` do with `horizon` and `timed`).

## Steps
1. The memo type and the stamps in the journal containers, states and records; `Core::epochs` first (reads: `ix.secrets`, `own_keys`, `keyset_parts`, `delete_hints`, the record chain, `account_view`, `NamesHeld`'s commits, keysets and timelines).
2. Each existing cache moved onto it and its hand wiring deleted with it: `secrets_read`, `head_keys`, `holders_named`, `reseal_quiet`, `key_access`, `inbox_actors`, `acting_memo`, `labels`, `published`, `links`, `bodies`, `live_bodies`, `copy_index`, `held_writes`, `account_views`, `ix.departures`; node-sync's `synced`, `rotated`, `keeps`, `vetted`. Done when `role_changed`, `role_generation`, the name matching in `Core::wrote` and `Engine::recheck` are gone.
3. Validity as memos per part (`Judge::part`), so a part is judged again only when what it was judged on moved, and a possession proof is checked once.
4. The debug checks: one sampled comparison in the memo type; whether `check_rebuilt` still runs after every transaction.
5. Node-sync's pass reading what moved from the memos instead of its own triggers (notes/node-sync-work-sets.md); decide after step 2.
6. Test setup: a world built once and copied per test (as `local_peer::Peer::fork` does for engine tests).

Counted checks for each step (work, never time): a pass with nothing new derives no key, checks no signature, decodes no commit; this setup's counts of key derivations, validity judgments and label builds bounded by small multiples of its commits and nodes.

## Method
- Instructions: `tools/icount target/debug/deps/it-<hash> --exact <test>` (perf_event_open counting works; `perf record` sampling is refused on this box).
- Profile: `valgrind --tool=callgrind --callgrind-out-file=OUT <binary> -q --test-threads=1 --exact <test>` (about 20 s); `callgrind_annotate --inclusive=yes --threshold=100 OUT` by function, `--tree=caller` for callers with call counts, `--tree=calling` for what a function spends on. Inclusive cost of a recursive function (`Decoder::item'2`, `Walk::walk'2`) counts each level again: use the non-recursive entry or exclusive cost.
- Wall per step: `eprintln!` of `Instant` elapsed after each statement of `world_waiting`.
