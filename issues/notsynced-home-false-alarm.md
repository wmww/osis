# NotSynced says home's holders may not read the account's own things
> Summary: Adding a thing whose admin is the account as an item of `home()` reports `NotSynced` "in a group whose holders may not read it", though it reaches the account's other nodes: `not_synced` (core/osis/src/write.rs) asks `Engine::may_read(group_actor(home), t)`, which lacks spec/sync-judgement.md §1's "an account's devices actor reads as its account does".
> Priority: normal
> Tags: engine, api

Seen: `w.create_in(db.me(), &[db.home()])` then commit (any single node; `api::a_local_thing_is_not_filed_spec_sync_set_1` drains it). `may_read` (core/engine/src/labeling/actors.rs, `Core::may_read`) checks the record chain and `role_of(x, reader actor)` only. Fix in one place (entitlement), so the diagnostic and every other caller agree with what sync carries; then the drain in that test goes.
