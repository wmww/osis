# Sim snapshot_rights seed 9317: a host re-upload/delete storm since whole-2b
> Summary: `snapshot_rights` seed 9317 fails with "message storm: 5000 deliveries without the queue emptying" at step 40: host s0 gets the same two commits (a `Content` delta and a `ContentSnapshot` of `s:reg.0`) uploaded under a fresh blob ID and deleted again, round after round. Passes on 02be71d2e (main before whole-2b, item 276). Not triaged.
> Tags: sync, retention, sim

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 9317 --only snapshot_rights --jobs 1` (or `osis_sim::replay("snapshot_rights", 9317)`); about 90 s in dev. Found in periodic run 15 (sim-sweep 9300+150; the only failure of 52 x 150).

Storm log (repeating): `s0 <label> added <fresh blob>: CommitId(adabc03c..) [(0, 0)] ["<thing> s:reg.0"] kind Some(Content)`, then `deleted` it, then the same for `CommitId(7a1010d7..)` kind `ContentSnapshot`, each round a new blob ID. Before step 40 the run is quiet (writes, a link cut at step 20).

Likely class: whole-2b's must-carry healing (spec/sync.md §6, `SyncEngine::must_carry`) against a right holder's delete, like issues/local-dating-delete-heal.md and the fixed keep-at-most skew churn (260d9619), but endless here rather than bounded by a clock gap. The scenario picks a purge-by set and keep-at-least half an hour or keep-at-most 0 after replaced per seed (`net/scenarios.rs` `snapshot_rights`); which one 9317 draws, and which node uploads, was not traced (`OSIS_SIM_TRACE`).
