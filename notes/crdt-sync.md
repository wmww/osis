# Commits, CRDTs and sync primitives
> Summary: Proposed model for commits, per-aspect delta-state CRDTs, history purging and Merkle sync; discussed with owner 2026-09-25, not yet in spec.

## Layers (each a canonical CBOR value with a hash)
- **Aspect state**: delta-state CRDT (join-semilattice, single `join` op). Carries its own causal context (set of dots absorbed). Stored per aspect; hashed by the Merkle tree.
- **Delta**: a small state of the same lattice; applying = join. Idempotent, order-free, tolerates duplicates. No op log or ordered delivery needed.
- **Commit**: signed header + one delta per touched aspect. Header: author node, actor, HLC timestamp, per-node seq, list of (tid, ak, delta hash), signature. Commit ID = hash(header). Bodies addressed by own hash.

## Guarantees
- Convergence under any delivery order (so "reorder/rebase" is meaningless; drop from spec).
- Atomic visibility: all deltas of a commit for tracked aspects joined in one storage txn, listeners after.
- Not isolation: concurrent commits merge; app invariants must be merge-compatible or repaired via listeners.
- Causality is intra-aspect only (tids may dangle per spec), so no commit DAG/parents required.

## History purge
- Delete bodies for one aspect; headers/signatures/IDs stay valid because bodies are by hash.
- Replacement = snapshot = the aspect's state sent as a delta.
- Caveats: sequence CRDT tombstones retain purged text until a hard reset (epoch bump); cross-aspect atomicity vs. purged aspect is lost for old commits.
- Guessable preimages: header keeps hash(delta), so a low-entropy delta (bool, PIN) could be brute-forced after purge. Fix: every delta body carries a random nonce (hash covers it; purge destroys it). Also key outward-facing hashes (deltas, states, chunks) with BLAKE3 keyed mode using a key derived from the thing/group read key; closes known-file confirmation on dedup'd chunks. Dots are not hashes, so a fully purged commit's header can be dropped too. Purge removes values, not the fact/time/AK of an edit.

## Merge per type (encoding is self-describing; schema picks it, enforced at write time; changing = breaking)
- scalars/tid/blob: LWW (HLC + node tiebreak). Knobs: `mv`; int/float `counter` (PN), `max`, `min`.
- string: LWW; `markdown`/`text` knob -> sequence CRDT over grapheme runs.
- struct: per-field. map: OR-map, recursive values. set: OR-set. Knob `add_wins` (default) / `remove_wins`.
- list: sequence CRDT, recursive elements; move = delete+insert (TODO).
- enum: LWW whole value; same-case payload merge deferred (needs epochs).
- **Reset/epoch** primitive: deltas tagged with epoch; join keeps max epoch, drops lower. Used by remove_aspect, delete_thing, map key removal, replace, hard purge. Observed-remove = add-wins flavor; epoch bump = remove-wins. Prior art: `clear` in Almeida/Shoker/Baquero "Delta State Replicated Data Types".

## Other consequences
- Merkle tree must hash *states* not values (equal values can have different contexts). Keep value hash for links/dedup; add state hash for sync. spec/data.md Hashing section currently says value hash.
- Sync flow: compare trees -> divergent aspects -> transfer whole commits restricted to tracked aspects -> snapshots where bodies pruned.
- Dots = (node tid, commit seq, index). Per-aspect contexts are sparse interval sets per node.
- Clock: HLC (wall ms, counter, node tiebreak, advanced on receipt, drift capped).
- API needs path-based ops (set field, insert/remove index, add/remove key, splice text, increment). `set_aspect` = structural diff convenience + explicit replace variant.
- `history` flag: state always kept; bodies kept for a retention window, forever with `history`. Undo = inverse delta.
- Chunking/prolly trees (see serialization.md) must apply to CRDT states too.
- Group Merkle tree: prolly tree over flattened sorted member set is simpler than following the cyclic hierarchy.

## Open (owner to decide in spec)
- `set_aspect` default: diff vs replace.
- remove_aspect / delete_thing: observed-remove vs epoch bump.
- Expose `mv` register to apps in v1?
