# Two chunk-tree implementations
> Summary: osis-commit (`tree.rs`: header lists) and osis-label (`tree.rs`: large values, pages) each write and read chunk trees; they agree today (osis-label tests/tree_compat.rs) but should be one module in osis-commit.
> Tags: commit, label

Deferred from the wave 2 integration pass because the large-values agent was rewriting osis-label's `tree.rs` (lazy-retry `TreeReader`, `BlobWriter` reuse, `Framing::keeps`); moving the file then would have conflicted throughout.

Planned move (wave 3 integration pass, after large-values merges):
- Move into osis-commit's `tree.rs` the label-independent parts: `TreeWriter`, `TreeReader`, `write_tree`/`read_tree`, `TreeSink`, `LinkSource`, `HashSink`, `node_plaintext`/`parse_node`, with their tests. Errors: map onto commit's `Error` (`Malformed`/`Corrupt` bad input; `Missing`; the size bound `Storage`, Local) or give the tree module its own small error that both crates convert.
- `Header::resolve` reads through `TreeReader` with a `LinkSource` (commit's `BlobSource::get` is the same contract); `Header` building writes through `TreeWriter` with a sink that takes prefix inputs (commit's `BlobSink`). Delete commit's `Reader`/`read_node` and level-by-level writer.
- Keep in osis-label what needs label types (`Prefix`, `frame`, `blob_id`): `Framing`, `BlobWriter`/`BlobReader` (the `PageSink`/`PageSource` adapters), `BlobSink`/`BlobFetch`/`BlobStore`, `MemoryBlobs`, `Written`, `Reuse`; `tree.rs` re-exports the moved items under the same names.
- Then tests/tree_compat.rs becomes redundant; delete it. Update notes/crdt.md (Implementation, chunk trees) and notes/sync.md (osis-label modules).
