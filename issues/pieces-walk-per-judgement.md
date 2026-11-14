# A body's pieces are walked whole each time its judgement moves
> Summary: `judge::body` runs `Engine::pieces` (the body's whole chunk tree) and reads every piece's own-store row on each settle of (S, c), so a small edit to a large value costs O(tree), not O(change).
> Priority: normal
> Tags: sync, engine

Measured (blobs walked by `pieces`, 3-node world, one writer, one store, one reader): writing a value walks 34 blobs for 4 pieces and 274 for 34 (linear); a 4-byte edit then walks 42 at 4 pieces and 342 at 34, about ten whole-tree walks per edit across the three nodes.

Why: the new commit links the whole tree (reused chunks), its judgement walks it, and any change to one piece's row (logged, arrived, a source showing it) settles the whole (S, c) judgement again, which walks the tree and reads each piece's rows.

Fix direction (Tess: shared memoization, not ad-hoc caches): a memo per node blob of what lies below it (immutable once held, so an edit's commit walks only its new path), and the per-piece acts (log, take, fetch, repair) judged per (S, piece) keys followed by the bodies that link them, so one piece's change judges that piece. Count at n and 10n pieces in a default test once fixed.
