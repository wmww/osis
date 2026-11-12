# A chunk's framing needs a header compaction deletes: large edits re-encrypt
> Summary: Reusing or deleting a chunk, tree node or page needs the blind (and delete-key list) of the header that introduced it (spec/sync.md §1 Chunk reuse, spec/crypto.md §7), but automatic compaction drops and deletes that commit at hosts while the live value still links its chunks, so a node that never received it re-encrypts every such chunk on its next edit: sim `large_edits` sends 1.5-3x an edit's new chunks (15 of 15 seeds). Needs a design choice.
> Priority: critical
> Tags: sync, crypto, retention

Blocks merging durable-compaction (the other five scenarios this issue named are fixed there).

**What happens** (`large_edits` seed 0): an account's two devices take turns editing an 8 MB value. Device 0 writes edit 1 (new chunks C1, C2), its trigger compacts at once (own snapshot S over its own live edit 1) and it deletes edit 1's commit blob at the host. Device 1 never fetched edit 1: it holds S, whose value links C1 and C2, but no header listing them (`Core::by_chunk` empty), so `Reuse::index` finds no blind, `Framing::keeps` cannot check the commitments, and edit 2 writes C1 and C2 again under fresh encryptions. Device 1 can never delete C1 or C2 either (`chunk_delete` needs the introducer's header). Without automatic compaction the same gap opens later: a commit forgotten under its author's own replaces takes its chunks' blinds with it.

**Options** (each a spec change):
1. Chunk commitments blinded by the chunk itself, e.g. `blind = kdf("chunk blind", link key)`, so anyone holding the link can check reuse and sign deletes; deleting then tries the node's own delete secrets against the prefix. Smallest moving parts; changes spec/crypto.md §7, spec/wire.md §5 and the label crate's framing.
2. A commit introducing a chunk a held body still links lasts as a header-only blob (must-hold) until no body links its chunks: one header per introducing commit of the live value (bounded by its chunk count); node-sync also must not forget such a commit (`forget_forgettable`: "no entry of a blob of it" read as covering its chunk list).
3. A snapshot lists the chunks its large values link with each one's introducer blind and keys (`ChunkEntry` grows): snapshots stay self-contained; headers grow by about 50 B per linked chunk.

Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 0 --only large_edits --jobs 1`.
