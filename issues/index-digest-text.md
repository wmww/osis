# Harnesses compare the index digest as text
> Summary: the order and walks harnesses parse `Engine::index_digest` with substring matching (e.g. ` {} ` for dropped parts, `snapshot_entries`), which breaks silently when the digest format changes (three agents hit it: deaths-shared-stamp, dropped-snapshot-receipts, retention-simplify). A structured digest (a typed struct the harness compares field by field, with the tolerances as named exemptions) would make format changes fail loudly.
> Tags: tests, engine
