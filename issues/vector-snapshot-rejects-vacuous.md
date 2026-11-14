# Snapshot reject vectors fail on arity, not their rule
> Summary: crdt/deltas.vec's snapshot reject cases ("register reset below its own write", "struct field below the struct's reset", "run carrying no write in a snapshot") are built by `snapshot_bytes` with 6 top-level items, so the decoder stops at "snapshot arity" (it wants 7: facts) and never reaches the rule the case names; `reject_case` checks only that decoding fails.
> Priority: low
> Tags: tests, vectors

Fix: `snapshot_bytes` writes the facts item and frontier entries the decoder requires (a frontier per session source, a fact per commit entry), and `reject_case` checks the error is the one its rule names (a map from rule to the decoder's `Malformed` text), so a vector can't pass on an earlier, unrelated rejection. Writer reject cases reach their rules today.
