# Spec audit 2 leftovers: engine parts not yet audited
> Summary: Parts of the engine part 2 of the spec audit did not compare against the spec: death re-dating after a validity flip or un-merge, "a drop is final", purge mechanics, epoch-start rounds, undo of ephemeral creations, crdt-model undo vs engine undo.
> Tags: spec, engine, crdt, permissions

The audited items (undo in effect, frontier decode, carrier covers, node-form role code, list presence, demotion order, `Slots` undo, register absent before, outermost absent, demotion scope as restored) were fixed on branch engine-audit-fix.

## Not audited
- Death re-dating after a validity flip or un-merge (`retention/deaths.rs` `rejudge_deaths`, `replay_all`) and spec/commits.md §5 "a drop is final".
- Purge mechanics beyond `known_purged`.
- Epoch-start rounds (spec/permissions.md §6).
- Undo of ephemeral creations (`unmake_ephemeral`).
- crdt-model undo vs `osis-crdt` undo line by line (the outermost-absent difference below map entries and list elements was one; the `Undone::restored` judgment of the engine and the model's `restored` closure are not compared).
