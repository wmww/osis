# dropped-snapshot-receipts
- `walks::reached` counts "commits with dropped parts" by a ` {} ` substring of `index_digest`'s commit line: adding a field after `missing {:?}` silently made every commit look dropped-free (coverage assert failed, not the oracle). Digest fields need a parse, not substring matching.
- Engine `snapshot()` takes schema bounds only from schemas the node has registered (by writing the aspect): a node that never wrote the aspect writes snapshots with no keep bounds. Cost a test iteration.
