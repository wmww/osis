# Copy expiry takes a writer's other values down with the copy
> Summary: Two honest paths still give a lasting value an expiring copy's T, so it vanishes at T: an undo takes the earliest T it copies for its whole delta per aspect, and the writer's per-op split falls back to whole-delta expiry when an op cannot run alone.
> Tags: engine, crdt

spec/requirements.md Deletion: a deletion reaches only what was deleted. spec/crdt.md §4.7 copy expiry splits a write so only the ops copying an expiring value take its T. Two paths still miss that:

- **Undo** (`undo::undo_expiring`, spec/crdt.md §4.6 "An undo takes the earliest T it copies"): one delta per aspect, its expiry the earliest of every copied dot. Remove an expiring entry and a lasting one in one write, undo it: at the expiring entry's T the lasting entry is removed again. Repro: `shred::undo_spares_lasting_values_past_a_copied_expiry_repro_spec_crdt_4_7`.
- **Writer fallback** (`write::copy_expiry`): each op is resolved alone to find what it copies; when one cannot (it builds on an earlier op of the write: post `m2`, then set a field of `m2`), every op takes the whole write's earliest T. React to an expiring entry, post `m2` and edit it in one write: `m2` goes at T. Repro: `shred::copy_expiry_split_spares_ops_building_on_each_other_repro_spec_crdt_4_7`.

Both are rule questions: an undo split by expiry per restored op (its ops are not `PathOp`s), and a writer split that keeps an op building on another in the other's delta (group ops by what they build on, then split the groups). Either may need Tess's call on how much machinery a rare shape earns (an app can avoid the fallback by writing in two mutations; an undo has no such escape).
