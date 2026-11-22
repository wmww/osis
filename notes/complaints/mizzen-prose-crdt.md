# mizzen-prose-crdt
- Notes cite tests that don't exist or aren't tests (`tests_model::crdt_equals_model`, a `revokes.rs` test, crypto's `validity::entry_under_two_keys` builder, "48 cases per run"): nothing checks a note's backticked names. A word-level check (every backticked identifier occurs in the code) found them in seconds; a policy rule could run it on notes.
- The crdt/keys notes are so dense that a meaning-preserving rewrite costs a full read of each plus the code; this pass mostly regrouped, fixed false claims and cut history, rather than shrinking them.
