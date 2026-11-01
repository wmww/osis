# Epoch establishment by names: what remains
> Summary: Names establishment (spec/crypto.md §4) is built: each rotation's history box names the departures its rotator held (and the keysets its holder-actor boxes name, and itself when it departs someone); a node uses an epoch only once it holds them. Left: the TLA rotation model still checks the old chain rule (step 4), and the review (step 5).
> Tags: security, keys, engine, tla

## Built (branch epoch-redesign)
- Rule, invariant comment: `osis_keys::EpochInfo::names_met`. Names: `rotation::departures::{names, keyset_names}`; held: `engine::secrets::NamesHeld`; establishment computed on read (`Core::own_epochs`), never stored.
- Deviations from the plan as approved:
  - `own` is the rotation commit's own `ts` and signer (`Names::departs`): `rotation_into` fixes the commit's `ts` before sealing. The plan's "held valid rotation commit, or an epoch start after it" stranded a late joiner after a `secrets.0`/`keys.0` compaction (it holds the removal's roles part but not the secrets body, so no rotation commit of the epoch: `unheld_rotation_counts_as_departed_partys_spec_crypto_4`).
  - The holder-actor hole (step 0) reproduced; the plan's rule (never seal to a holder actor's keyset older than one a box at an established epoch names) fails: the rotator's own rotation removes that box, and the next re-seal boxes the older keyset. Closed instead by names: a rotation names, per holder actor it boxes and role, the commit that wrote the keyset its box names (`epoch_intro`). Test `holder_actor_keyset_named_spec_crypto_4`. Cost: one name per holder actor and role.
  - `Keyset::supersedes` stays, as a set of epochs (the plan's choice): nodes not holding a new epoch's secret need it to supersede.

## Remaining
- Step 4 (TLA): core/test/tla/rotation's `Est` is still the chain rule (ASSUMPTIONS.md "Established epochs"); replace with names, add a host or peer withholding a removal indefinitely and the negative control (`nm` = own removals only) as an expected failure; update ASSUMPTIONS/README/AMBIGUITIES. The scratch probe in the old version of this issue passed every MC but `MC_grant_remove` (not finished).
- Step 5: review hunting remnants; gate; tier 2: rotation `_large` x5 (`withheld_departures_leak_nothing_large` is new), forks, perm tier 2, sim permission list.
- Name completeness is the risk: `names` is a superset by construction (every lowering or `until`-passed edge write after the epoch start, every audit drop). End to end: the engine harness (removals, demotions, self-removals; with `more`, grants and `until`s that pass: seed 3 leaks with the `until` clause dropped), `audit_dropped_grant_named_spec_crypto_4` (fails with the audit clause dropped: only an owner-chain demotion makes it load-bearing), `holder_actor_keyset_named_spec_crypto_4`. No random harness covers holder actors or multi-device persons.
- Open: issues/keyset-names-start-escape.md (keyset names met by a roster snapshot).
- Orthogonal, unchanged: issues/fork-held-by-non-rotators.md, issues/fork-choice-keys0.md.
