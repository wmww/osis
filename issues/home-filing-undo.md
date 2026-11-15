# Home filing breaks undo of delete and redo of creation
> Summary: a thing filed under home (created, listed nowhere synced) can't have its delete undone or its undone creation redone: both write home's `group.0` back, which keeps no history.
> Priority: normal
> Tags: engine, osis, tess-call

A write as the account files what it creates that nothing synced holds under home as a subgroup (spec/sync-set.md §1 Filing). Undoing that thing's `delete`, or redoing its undone creation, re-adds the home listing: an inverse restoring a removal, which needs home's `group.0` history kept (spec/commits.md §7). Home has no history setting, so both fail `NotUndoable{NotKept}` even when the thing's own setting keeps everything. Before filing, a thing listed nowhere undid and redid fine. Kit and the app are not hit: they list what they make in their main group (kept a day, `keep_a_day`), so nothing of theirs is filed.

Reproduce (core/osis tests): `create` + `keep_all(t)` + a kept write; then `delete(t)` and `undo(Scope::Thing(t))` → `NotKept`; or `undo` the creation, then `redo` → `NotKept`.

Options:
1. Home keeps `group.0` history by default: the account's creation writes a `retention^.0` entry on D (a day, as kit's `keep_a_day`). Smallest change; a default config choice (Tess: keep config open), and past the bound the same failure comes back.
2. Engine (Fathom's pick): a `group.0` part whose writes only list or unlist the thing being deleted or restored needs no kept history of the group, as `undo::lists_only` exempts the creation's own undo. Blocker: both failing cases invert a removal, and a set removal leaves a tombstone `(dot, R_elem)` with no value (spec/crdt.md §4.2, §5.5); the removing part's body holds none either. So "only unlists x" cannot be judged from the group's state, and the re-add cannot name its tid without the unkept add part's body (which differs by node, against spec/commits.md §7). The add direction (undoing a redo or an undelete: removing listings of x the commit added) is judgeable from state but fixes neither case. Making it work needs the unlisting to keep its tid in state, e.g. delete's and an undone creation's removal of a tid written as a value removal naming it (§5.5 `(stamp, v, parts)`, which keeps the hidden element and names `v`): a CRDT writer change, and those records are never collected (growth per delete).
3. Accept and document: apps that want undo keep home's history themselves.
