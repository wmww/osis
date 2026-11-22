# mizzen-notes-size-3
> Summary: Workflow notes from the size cut of notes/node-closure.md, sync-inbox.md, sync-store.md and sync-status.md.

- Code docs drift too: units.rs's module doc named an `out_of` that does not exist and left out `Ctx::Ticket`; code_refs never reads code comments, so nothing catches a stale name there.
- The work counts copied into node-closure.md were exact numbers the tests never assert (they assert shapes: constant, linear); copy the shape a test checks, not a run's output.
- doc_refs catches a test comment pointing at a section only by its lead words: renaming a section to a bullet broke `record.rs`'s pointer; grep `notes/<file>` across code before reshaping a note.
