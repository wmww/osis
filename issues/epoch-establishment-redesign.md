# Epoch establishment by names: what remains
> Summary: Names establishment (spec/crypto.md §4) is built: each rotation's history box names the departures its rotator held (and the keysets its holder-actor boxes name, and itself when it departs someone); a node uses an epoch only once it holds them. Left: the review (step 5).
> Tags: security, keys, engine, tla

## Built (branch epoch-redesign)
- Rule, invariant comment: `osis_keys::EpochInfo::names_met`. Names: `rotation::departures::{names, keyset_names}`; held: `engine::secrets::NamesHeld`; establishment computed on read (`Core::own_epochs`), never stored.
- Deviations from the plan as approved:
  - `own` is the rotation commit's own `ts` and signer (`Names::departs`): `rotation_into` fixes the commit's `ts` before sealing. The plan's "held valid rotation commit, or an epoch start after it" stranded a late joiner after a `secrets.0`/`keys.0` compaction (it holds the removal's roles part but not the secrets body, so no rotation commit of the epoch: `unheld_rotation_counts_as_departed_partys_spec_crypto_4`).
  - The holder-actor hole (step 0) reproduced; the plan's rule (never seal to a holder actor's keyset older than one a box at an established epoch names) fails: the rotator's own rotation removes that box, and the next re-seal boxes the older keyset. Closed instead by names: a rotation names, per holder actor it boxes and role, the keyset epoch its box names (first the commit that wrote it, which a roster snapshot met). Tests `holder_actor_keyset_named_spec_crypto_4`, `holder_keyset_name_not_met_by_roster_snapshot_spec_crypto_4`. Cost: one name per holder actor and role.
  - `Keyset::supersedes` stays, as a set of epochs (the plan's choice): nodes not holding a new epoch's secret need it to supersede.
- Keyset names (branch keyset-names) name the holder actor's keyset epoch, not the commit that wrote it, met by a held valid `keys.0` body writing or listing it (no epoch-start escape; was issues/keyset-names-start-escape.md).
- Step 4 done (branch keyset-names): core/test/tla/rotation's `Est` is names (removals the rotator held, a holder actor's keyset epoch), with `MC_withhold` (a removal withheld forever), `MC_keyset`, and negative controls `MC_names_own` and `MC_keyset_nonames` as expected failures (AMBIGUITIES.md R16).

## Remaining
- Step 5: review hunting remnants; gate; tier 2: rotation `_large` x5 (`withheld_departures_leak_nothing_large` is new), forks, perm tier 2, sim permission list.
- Name completeness is the risk: `names` is a superset by construction (every lowering or `until`-passed edge write after the epoch start, every audit drop). End to end: the engine harness (removals, demotions, self-removals; with `more`, grants and `until`s that pass: seed 3 leaks with the `until` clause dropped), `audit_dropped_grant_named_spec_crypto_4` (fails with the audit clause dropped: only an owner-chain demotion makes it load-bearing), `holder_actor_keyset_named_spec_crypto_4`. No random harness covers holder actors or multi-device persons.
- Orthogonal, unchanged: issues/fork-held-by-non-rotators.md, issues/fork-choice-keys0.md.
