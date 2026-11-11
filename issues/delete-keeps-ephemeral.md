# A delete that writes nothing durable keeps the thing's ephemeral values
> Summary: `w.delete(t)` on a thing with no durable content left and no group memberships (only ephemeral values) commits nothing, so `Engine::write` never reaches `retention::memory::drop_things`: the ephemeral values, their reference rows and so its backlinks stay, against `Write::delete`'s doc ("its ephemeral values are dropped here"). The fix needs a rule for what listeners hear of a drop with no commit.
> Priority: normal
> Tags: engine, api

Where: `ephemeral::write` (core/engine/src/ephemeral/mod.rs) runs `drop_things` inside the transaction of `commit_in` only when that commit exists; `commit_in` returns `None` for a mutation whose only content is `deleting`. `dropped_event` stamps `Event::Ephemeral` with the durable commit's id, so a drop with no commit has no `Origin`/`Stamp` to give.

Options: (a) a delete always commits (e.g. the `created.0`-only case still writes a removal, so it is an undoable step like any delete); (b) drop with no commit and tell listeners a derived change (a `DerivedFrom` for it). (a) keeps one rule (a delete is a commit; undo restores nothing ephemeral either way). Repro: delete a thing whose only values are ephemeral; `at(t, eph).get()` still reads them.
