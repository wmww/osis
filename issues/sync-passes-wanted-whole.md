# passes_wanted is one whole value
> Summary: `Engine::passes_wanted` is one memo over every read sync ID, recomputed whole (O(read sync IDs + ties + role commits on their actors)) at each pass noted and each role commit applied, and status follows it as one `Effects` key, so a node's first passes of N sync IDs cost O(N²).
> Priority: low
> Tags: engine, sync

Each `note_complete_pass` writes `ix.passes`, which the memo read, so the next `passes_wanted` derives every want again and status diffs the whole map. Fast by construction wants it per sync ID: a memo keyed by S (its wants from S's actor's role commits, the ties whose scope holds S, its noted pass), status following each S it holds through its own `Effects` key, as the store follows `thing_sync` per thing.
