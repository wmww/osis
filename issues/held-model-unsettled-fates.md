# held-model: fates that never settle, and a joint reader judging valid what the full node judges invalid
> Summary: on main (595fa6faf) held-model's own properties fail at two seeds: `props::settled_histories_keep_their_laws_large_spec_commits_5` and `props::late_commit_converges_after_repair_large_spec_commits_5` at seed 610247967463 ("fates did not settle"), and `spec_joint::joint_one_sync_id_and_key_parts_act_as_everything_plain` at wide 610247967233 (J-act, J-logged).
> Priority: normal
> Tags: tests, held-model

- Replays (held-model depends on no osis crate, so these are the model alone): `OSIS_HELD_START=610247967463 OSIS_HELD_SEEDS=1 cargo test -p held-model --test it -- --ignored --exact props::settled_histories_keep_their_laws_large_spec_commits_5 props::late_commit_converges_after_repair_large_spec_commits_5`; `OSIS_HELD_START=610247967233 cargo test -p held-model --test it -- --ignored --exact spec_joint::joint_one_sync_id_and_key_parts_act_as_everything_plain`. Found by a gate at offset 610247967197.
- props: the repair loop stops with parts still `NeverReceived`/`MustDrop`/owed: a `Snapshot` commit's register write among them.
- joint: `wide 610247967233`, step 16, sid 11, commit 23: the one-sync-ID reader `Valid`, the full node `Invalid`. Which side is wrong is not settled.
