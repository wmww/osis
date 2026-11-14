# sync-notes complaints
- tools/doc_refs.py catches pointers to deleted notes, but nothing catches notes citing deleted code or tests (`SyncEngine::x`, osis-node `scale::y`): finding those took grep heuristics per note, and some citations of deleted tests remain in notes not walked line by line.
- The deletion commit dropped every osis-node `scale::`/`growth::`/`memory::` test, engine-level ones included, so notes/test-scale.md's counted rows have no test now (listed under Checks to restore).
- tools/bin-at still defaults to `-p osis-node`, a crate that no longer exists (docs-only branch, not changed here).
