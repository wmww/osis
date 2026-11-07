# A delete that makes two commits
> Summary: `delete` of a thing with ephemeral aspects (and undoing a creation, and their reverts) makes a durable commit plus a memory commit under one `ts`, which a peer may hold one without the other. When the delete takes the thing out of every closure, node-sync places the memory half nowhere, so holders keep reading the thing's ephemeral values until they restart. Options: a durable floor, or refusing such deletes.
> Tags: engine, sync, spec, tess-call

## The case
`Engine::write` (`Mutation::deleting`) and `revert_batch` (`reset_ephemeral`) write a thing's durable resets and group removals in the durable commit and its ephemeral aspects' resets in a memory commit under the same `ts`. A delete is not on the wire: it is resets of every aspect the deleter holds and its group removals (notes/api.md Writes), which a receiver cannot tell from "this commit clears these aspects", and the ephemeral resets are per observed dot, which only the deleter knows.

The memory half is placed by node-sync's next pass under the labels whose closure holds the thing. The durable half already removed it from its groups, so when it was in no other synced group the memory half goes nowhere: holders keep the thing's ephemeral values (a deleted window's state, a cursor) and read them, and `has_content` stays true there, until they restart (`deleted_thing_stays_deleted_at_holders_spec_sync_9` and `undo_of_creation_reaches_holders_spec_crdt_4_6` assert the deleter's side only).

## Ways out
- **Durable floor**: a new core durable aspect, say `ephemeral_floor.0` (a register of a `ts`), written by `delete` in its durable commit; every node reads the thing's ephemeral writes stamped at or below it as nothing and may forget them. One commit, reaches holders with the removal. Undoing the delete restores the floor (values come back where still held). Costs: a core aspect and a cross-class read rule; a floor drops concurrent unseen ephemeral writes stamped earlier too (what a delete means anyway).
- **Place by the closure the commit was written in**: the memory half goes under the labels the durable half went under. Needs node-sync to remember a placement per commit pair; more machinery than the floor.
- **Refuse**: `delete` of a thing with ephemeral state is `Invalid` until the app removes that state in a commit of its own (which then goes while the thing is still in its groups). Every app deleting a thing with a cursor writes two commits by hand. It is the rule a `Write` mixing durable and `~` writes already follows (one write, one commit, nothing left for Tess on Atomic), but undoing a creation would need the same refusal, so an undo stack fails on any window with ephemeral state.
- Rejected: receivers forgetting others' ephemeral writes on a thing in no synced closure. It also fires on a plain removal from a group, and each holder's own writes stay.

## Left
- spec/requirements.md (Atomic, "A commit is never split") conflicts with this case, and its Limit lists only expiry and `nobody` mixes: a requirements note for Tess with this call.
- `core/osis/src/lib.rs` "One write, one commit" still says a `Write` is one commit; `Write`'s doc names the exception.
