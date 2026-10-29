# dropped-snapshot-receipts
- `walks::reached` counts "commits with dropped parts" by a ` {} ` substring of `index_digest`'s commit line: adding a field after `missing {:?}` silently made every commit look dropped-free (coverage assert failed, not the oracle). Digest fields need a parse, not substring matching.
- Engine `snapshot()` takes schema bounds only from schemas the node has registered (by writing the aspect): a node that never wrote the aspect writes snapshots with no keep bounds. Cost a test iteration.
- Review: `walks::reached` now reads `Engine::drop_counts`; snapshot bounds filed as issues/snapshot-bounds-unknown-schema.md. A release scale run (4000 snapshots) took 204 s of fill for a 5 ms read: the fill (one commit+snapshot+tick per step) dominates.
