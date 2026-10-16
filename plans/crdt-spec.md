# Spec the CRDTs
> Summary: Write an exact spec of every v1 merge type (state, delta wire encoding, join, read, ops, embeddings), check it with a reference model, before the real implementation.
> Tags: crdt

Source: notes/crdt-sync.md (semantics mostly decided), notes/versioning.md (encoding lattice). Output: a spec document (`spec/crdt.md` or similar) precise enough that a second implementation would converge byte-for-byte on wire deltas.

## Steps
1. **Common pieces**: dot forms (node-table index + counter; commit-ID + index, marked per commit), HLC layout and comparison, reset register, how a delta names its encoding, how element IDs compress into runs.
2. **Per type**, each with state, delta encoding (CBOR), join, read, local ops -> delta, undo (cancel per dot), un-merge by author dot, tombstone lifetime:
   - LWW register (scalars, tid, blob), counter, max, min
   - struct (per field), enum (case register + payload)
   - set, map (element store, key -> live dots index, nested write deltas carrying the key)
   - text/list movable CRDT: linearization (RGA order by `pos` write time), cycle breaking with the second `pos` slot, unknown anchors, range move, cut/paste, delete/undelete. Write as pseudocode with worked examples (FOOBAR case etc).
3. **Lattice embeddings**: list every upgrade edge (register -> text, int -> counter, ...) and the conversion; the no-embedding fallback.
4. **Large states**: how million-key maps and long texts are paged into store units and chunked for snapshots and compaction (notes/local-store.md Open, notes/serialization.md links); what a snapshot delta of a chunked state looks like on the wire.
5. **Structural diff**: `set_aspect` diff algorithm per type (list heuristic caveat).
6. **Reference model**: small, slow, obviously-correct implementation plus proptest: convergence under random delivery/duplication, single-writer matches sequential model, idempotence, embeddings commute with join. Fuzz the decoder.
7. Benchmark text state size against the automerge-paper trace (target 1.5-3x plain text) before fixing the text encoding.

Ambiguities found go to the owner only if they change user-visible semantics; otherwise decide and record in notes/crdt-sync.md.
