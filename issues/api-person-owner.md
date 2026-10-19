# Stores created before membership flows have a node-owned person actor
> Summary: Until membership-flows wires `Osis::create` to a recovery-key-owned person actor, `create` makes the person a plain thing owned by the node (no `/keys`, no recovery card, home group without a label); the second half must migrate or reject such stores.
> Tags: api

Today (crates/osis/src/handle.rs `Osis::create`): person = thing owned by the node, home = group owned by the person; both tids in node `app_record`s `person`, `home`. Everything an app creates with owner `me()` is then owned, transitively, by one device: never shareable to other devices of the person, and lost with the device.

When flows land, `create` must produce the real person actor (recovery key owner, this node as admin, `/keys`, home label) and the card. Old stores:
1. (recommended) Reject at `open` with a clear error when the `person` record names a node-owned thing (no MVP data to keep: no app has shipped on this shape).
2. Migrate: create the real person actor, `move_thing` every thing owned by the old person (copies with `/was`), rewrite the records. Costs the move machinery for a pre-release format.
