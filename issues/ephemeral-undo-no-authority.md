# Reverting ephemeral writes skips the write check
> Summary: `revert_change` on an ephemeral change checks no authority: a node that lost write still writes the inverse, and on undoing a creation removes placements, locally and on the wire. Spec/crdt.md §4.6 "The undoing node must hold write on the thing, else there is no undo"; a normal ephemeral write and a durable undo both check.
> Tags: engine, permissions

`revert_inner` (core/engine/src/ephemeral/log.rs:225): `ephemeral_undo` and `unmake_ephemeral` resolve writes, the check at :255 runs only when `confined` (`revert_as`), and `apply_ephemeral` joins and sends with none. Compare `ephemeral/mod.rs:353,360` and `undo::undo_in` (`check_authority`, `role_of` in `unmake_ops`). `unmake_ephemeral` also removes placements from every `placed.0~` listing the thing without the durable path's "that the undoing node may write".

Input: a writes ephemeral aspect on durable thing t, a is demoted to read, a reverts. Holders drop the write as unauthorized; a reads its own undo, so it reads differently until the session ends. Traced, not run.

Fix: check every resolved write in `revert_inner` as the write path does (`Superseded` or `Permission`), and filter placements by `may_place`.
