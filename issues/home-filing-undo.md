# Home filing breaks undo of delete and redo of creation
> Summary: a thing filed under home (created, listed nowhere synced) can't have its delete undone or its undone creation redone: both write home's `group.0` back, which keeps no history.
> Priority: normal
> Tags: engine, osis, tess-call

A write as the account files what it creates that nothing synced holds under home as a subgroup (spec/sync-set.md §1 Filing). Undoing that thing's `delete`, or redoing its undone creation, re-adds the home listing: an inverse restoring a removal, which needs home's `group.0` history kept (spec/commits.md §7). Home has no history setting, so both fail `NotUndoable{NotKept}` even when the thing's own setting keeps everything. Before filing, a thing listed nowhere undid and redid fine. Kit and the app are not hit: they list what they make in their main group (kept a day, `keep_a_day`), so nothing of theirs is filed.

Reproduce (core/osis tests): `create` + `keep_all(t)` + a kept write; then `delete(t)` and `undo(Scope::Thing(t))` → `NotKept`; or `undo` the creation, then `redo` → `NotKept`.

Options:
1. Home keeps `group.0` history by default: the account's creation writes a `retention^.0` entry on D (a day, as kit's `keep_a_day`). Smallest change; a default config choice (Tess: keep config open), and past the bound the same failure comes back.
2. Engine: a `group.0` part whose writes only list or unlist the thing being deleted or brought back needs no stored content beyond that tid (as `undo::lists_only` already exempts the creation's own undo): extend it to delete's undo and along an undo chain rooted at a creation (its redo, the undo of that redo). Principled, but an engine undo rule change (Fathom) and a spec/commits.md §7 change; judged from state alone, so every node agrees.
3. Accept and document: apps that want undo keep home's history themselves.
