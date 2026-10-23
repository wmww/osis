# Un-merge of a nested write depends on delivery order
> Summary: A node that joins a valid writer's nested write inside an entry before learning (from a snapshot) that the entry's creation is invalid keeps the entry; learning it first drops it. Un-merge must be a function of the held set.
> Tags: permissions, node, security

Repro: `cargo test --workspace --test it entry_created_after_demotion_write_first -- --ignored` (osis-node `validity.rs`).

Bob, removed, creates map entry "late" offline; Carol (unaware) writes inside it and compacts. Dave holds Alice's and Carol's commits and Carol's snapshot, none of Bob's. With the snapshot applied first, "late" goes with Carol's write under it (as at Alice). With Carol's commit applied first, "late" stays.

Found when the reader rule of spec/crdt.md §8 (a carried stamp above the snapshot's `ts` is bad input) made the test's hand-built snapshot honest: it had been dated before the writes it carries, so it sorted, and was delivered, first.

Likely cause: `join_into_state` strips an invalid creation's dots (and the nested writes under it) from each body before it joins; a later judgment that a carried write is invalid (`note_authors` / carried judgments) does not re-strip the bodies already joined, or the rebuild does not treat another author's nested write under the now-invalid entry as going with it.
