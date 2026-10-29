# Undo can revert a thing's creation, leaving it unplaced but not deleted
> Summary: `db.undo(Scope::Thing(t))` picks the creation commit once nothing newer is left; that commit also placed the thing, so undoing it leaves a thing in no group: gone from every app, not deleted. The app copies core's undo picking to skip it.
> Tags: core-ask, api, owner-call

Repro: create a thing (placed in a group), call `undo(Scope::Thing(t))`: placement is gone, the thing remains.
Ask: decide what undoing a creation means (delete the thing, refuse, or never pick creation in a thing scope), and expose "what would undo revert" so a UI can label or disable its button without reimplementing the picking (app/src/data.rs `next_undo`).
