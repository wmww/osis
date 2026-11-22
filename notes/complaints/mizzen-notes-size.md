# mizzen-notes-size
> Summary: Workflow notes from the size cut of notes/crdt.md and notes/local-store.md.

- Module docs (`//!`) already said most of what the notes' Implementation sections did (seq_lin, stream, pager, nodelog, Stamping): notes and docs drift apart unseen. A note pointing at the module doc, and the doc not pointing back for the same facts, avoids a circular "details in the other one" (pager.rs still sends its row layout to the note).
- `tools/code_refs.py` passes a name a comment alone keeps, and doc_refs checks only that a section exists, not what a `Section: claim` pointer claims: the false "store keeps each body's first and last death" line passed both.
