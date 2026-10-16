# CRDTs and commits: rationale
> Summary: Why spec/crdt.md and spec/commits.md look the way they do: owner decisions, design choices with reasons, known anomalies, rejected alternatives, implementation hints, the reference model `crdt-model/` and its tests, text size measurements, worked examples (cited by tests), research pointers.

## Owner decisions
- One conflict rule everywhere: every state element carries a timestamp and an author dot, later wins, removal is a reset. No causal contexts; no multi-value register.
- Collection elements are identified by creation dot; a removal resets the observed dots, so an add the remover never saw survives. Tombstones carry no content (no fingerprint).
- `set_aspect` diffs structurally by default; an explicit replace resets.
- Every composite merges recursively down to leaf registers; enum cases never merge with each other.
- Movable text/list CRDT ships in the MVP, as good as we can make it, with whatever fuzzing and testing that takes.
- Apps see plain values and listeners; no CRDT details reach the API. A lost concurrent write looks like any LWW loss.
- Authenticated malicious writers are out of scope (gaming the HLC to win LWW is not a concern).
- No tombstone compaction: worse merging after long separation is acceptable, discarding edits is not.
- Retention classes, purge per commit without batching, expiry (spec/commits.md §5, §6).
- Undo is per actor by default, plus an API listing every change in scope from which an admin may undo others' changes.
- Accepted: a node receiving a multi-aspect commit after one delta was purged applies the rest, so it may briefly see an aspect combination no author produced.

## Design choices and why
- **Stamps.** HLC tiebreak lives in the dot's source, which also works for commit-form dots (the commit ID is unknown before signing). Commit-level writes share one delta stamp: saves 3–6 bytes per write and most intra-commit ordering questions; a delta still consumes at least one counter so frontiers cover every commit.
- **`>=` survival** lets a replace and the embeddings put content at the reset's own stamp.
- **Presence stamp**: an explicitly empty collection exists, one emptied by removals stays present, `remove_aspect` makes it absent. Only `W` is stored and the rest computed, so expiry can lower presence. `W` is always encoded: omitting it under a greater inner stamp broke un-merge.
- **Derived sources** give the register → text embedding one identity per character without a third dot form. A `Derived` record goes with its write, matching a node that only saw the value-less register.
- **Bag contributions are set elements**, so undo of an increment is an idempotent element reset. No bag GC: dropping non-extreme max/min elements or folding contributions changes the read under a later reset landing between the folded stamps, and under expiry of the extreme. Bag reads are order-independent (exact int sums clamped, float sums in dot order, IEEE totalOrder).
- **Enum payloads filed per case**: a writer editing case A's payload while another switched to B must not flip the value back to A with a half-written payload; the newer payload write stays hidden until a reset (tension 23).
- **Map tombstones live until the map is reset**, because an older nested write may still arrive and must lose. Same-key entries are not merged into one: the dots are different authors' identities, and joining at read time gives the same value with no rewrite.
- **Set tombstone GC** is safe once both the add and the reset commits are applied: only a causally later undo can target the dot. The reset is folded into `W` so presence never depends on GC.
- **Undo of a text/list insert is a deleted flag**, not an element reset: keeps the anchor.
- **Sequence records are never pruned.** Dropping element records on reset hid a concurrent newer insert anchored into the removed text until the next reset, violating "a newer write never loses to an older removal". Now resets leave bare anchors and the insert lands after the new content, as in Yjs. Emptiness counts records, or anchor survival would depend on arrival order. Cost: a sequence's state never shrinks (tension 14), about one byte per run.
- **Creation write kept apart from the top-2 positions**: needed to encode runs and to give text content a stamp.
- **Cycle breaking** demotes the oldest move in the cycle, the one the other movers did not know about, keeping the newest intention. Falling back twice needs three or more concurrent moves over the same elements; END keeps content visible instead of hiding it.
- **Move** writes `pos` only for range roots (rewriting interior elements changes their sibling keys and reorders concurrent neighbours). The range spans deleted elements inside the selection; outside subtrees are re-anchored in reverse visual order (found by the model's sequential test). Delete is a flag, not a move to a trash position, which would drag concurrent inserts along.
- **Encoding slots.** The first draft joined unrelated encodings destructively (later encoding wins, loser becomes a reset). With eager embedding that is not associative: `(register ⊔ counter) ⊔ text` ended as a counter and `register ⊔ (counter ⊔ text)` as a text (found by the model's join-law test). Keeping the register as its own slot makes the state a product of lattices. Cost: in a `string` → `text` upgrade the last register write is stored twice until a reset. Register edges are total so a value-less write embeds like its valued copy.
- **Expiry is value erasure, not a floor.** It changes no stamp or order, only whether a value is known, so it commutes with join and arrival order; a late older write still loses to the expired one. Dropping the commit's resets instead would let content they pruned survive on a node that received it after T. A floor at T diverges if applied only when the expired write wins (a write stamped between the commit and T wins on some nodes, loses on others), and expires others' newer writes if applied to every register the commit wrote.
- **Drift cap parks** commits from the future instead of holding the clock back, so a wrong clock harms only its owner's writes. Parking is silent: a device 90 minutes fast has its writes held by everyone for 90 minutes, and blind nodes cannot tell it. Hence the corrected clock (spec/sync.md §6): a device fixes its stamps at its first connection and later writes are not parked; only writes it stamped before that wait. A lying peer can shift a node's clock, which harms that node's own writes or admits writes a little early; estimate over several peers, preferring pinned servers. HLC receipt already pulls a slow clock forward.
- **Diff takes the writer's view**: without it an old writer's save of a `set<struct>` removed every element a newer writer had extended and added a stripped copy. The diff algorithm itself is not normative, only "kept elements keep their dot".
- **Second dot form** (commit ID, index): unlinkable, and collision-free when several devices sign with one key (per-device counters under a shared key let any holder reuse another's dot and knock out its edit). Its cost falls only on such commits: runs do not continue across commits, one 32-byte `sources` entry per foreign commit, witnesses list commits.
- **Every state element carries its dot**, so un-merge and frontier attestations are uniform.
- **No commit DAG**: causality is intra-aspect only, tids may dangle.
- "Repair via listeners" only works if the repair is a deterministic function of state; otherwise two nodes ping-pong.
- Encoding IDs live in the delta, not in the header.

## Known anomalies (all convergent)
- A move displaces a concurrent insert made right after the moved range's predecessor (example below).
- An enum payload edit concurrent with a case change stays hidden (tension 23).
- A field write concurrent with a container removal resurrects the container with that field alone (tension 24).
- While a text aspect is in transition, every save by an old LWW app wipes concurrent older text edits; old code has no CRDT.
- The list diff pairs changed entries in order; a misaligned pair becomes delete+insert and loses concurrent edits to that entry. Apps editing list entries concurrently should use path ops.
- Un-merge over state is approximate: position registers keep two writes, and register values the invalid author overwrote come back only from retained bodies.
- Undo of a reset re-adds content with fresh dots (the old dots stay below the reset forever), so a later undo of an original element no longer cancels its restored copy; only out-of-order selective undo sees this. Bag undo re-adds contributions without a reset so concurrent newer contributions survive; other encodings' reset undo is a `replace` and wipes concurrent newer writes inside the value.

## Rejected
- Wall-clock staleness horizon for tombstones: nodes separated longer than the horizon diverge or lose edits; any independent reset-style compaction has the same problem.
- LWW-element sets/maps: the tombstone names a value hash or key (a fingerprint under `purge`) and cannot be dropped without stability information.
- OR-set/OR-map with causal contexts: same add-wins semantics as dot addressing but a version vector in every state and delta. Possible later if map tombstones ever matter: stability-based GC (needs frontiers, stalls on offline members).
- Terminal reset / retire marker in the encoding lattice: representation changes are transitions to new IDs.
- Attributing state elements through commit headers instead of dots (zero bytes in state, history lookup at revocation): not uniform.
- Columnar or bit-packed encodings (20–30% gain, not worth leaving CBOR); dropping stamps from deletions (changes undo, and deletions are no longer the dominant cost).

## Implementation hints (non-normative)
- Linearization: cache the order and tree; a delta touching k elements re-places those k subtrees; a cycle recomputes only its strongly connected component.
- Large states page in the local store like snapshots (notes/local-store.md, Units). Very long texts (tens of MB) load fully for linearization; a subtree-count index is a later optimization.
- Maps need a local `key -> live dots` index.
- If a concurrent edit resurrects an element whose content this node dropped, request the specific blobs that carried it.
- Cut/paste: the client remembers the cut dot ranges beside the clipboard text; paste emits move + undelete if the clipboard still matches, else a diff. Optional osis clipboard MIME type with (aspect, ranges); the protocol has no clipboard concept.
- Undo stack is derived, not stored: the actor's own commits in scope (a set of aspects or a group) minus undone ones, plus undo commits for redo. Replicates for free, so undo works across devices. A node keeps its own bodies and pre-reset snapshots locally for the undo horizon.
- A list path op resolves index paths against local state at write time; deltas never carry indices.
- Commit floor: a minimal commit is about 300 bytes once nonce, framing, tag and padding count, plus a 49-byte wrap per label and a prefix of about 35 bytes. Fine for editing workloads; revisit only if huge commit volumes appear (owner).

## Reference model (`crdt-model/`)
A small, slow, obviously-correct implementation of spec/crdt.md: `State` (fully resolved stamps), join, prune, read, the ops, un-merge, the wire encoder/decoder (own canonical CBOR subset), embeddings, diff. Not the implementation; the implementation will be tested against it. Property tests (`tests/props.rs`):
- convergence under random delivery orders, duplication and omitted prefixes: equal reads and equal encoded states;
- join laws on random states, within and across encodings (every association and order of three states);
- single writer vs a sequential model after every op;
- wire round trip and byte-identical re-encode; decoder never panics on random or mutated input;
- embeddings commute with join; a register delta joined into a text equals its embedding joined;
- undo (single writer), diff (`read(join(S, diff(S, v))) == v`);
- expiry: random expiring commits stripped at random points, equal to join-then-strip; strip commutes with join and is idempotent; value-less registers embed like stripped valued ones;
- snapshots: round trip with frontiers, frontiers equal last counters, bootstrapping from a snapshot reads the same;
- the worked examples below.
Not modeled: set tombstone GC by received ranges; the schema projection of the diff (the model's diff is untyped).

## Text size
Benchmark `crdt-model/src/bin/text_bench.rs`: Kleppmann's automerge-paper trace (259,778 single-character edits, final text 104,852 bytes, 182k elements of which 77k deleted), one writer, net effect per commit, encoded as a foreign node's snapshot. Target was 1.5–3x the plain text.

| edits per commit | commits | commit table | runs | flag writes | snapshot | ratio |
|---|---|---|---|---|---|---|
| 1 | 259,778 | 2.47 MB | 6,288 | 77,463 | 4.64 MB | 44x |
| 10 | 25,931 | 243 KB | 6,062 | 12,721 | 687 KB | 6.6x |
| 100 | 2,598 | 24 KB | 6,000 | 5,431 | 331 KB | 3.2x |

Content is 105 KB and run records about 150 KB (6,000 runs at 25 bytes, the floor for this trace). The rest scales with commits (about 9 bytes of commit table plus 4 of run segment each) and deleting commits (about 8 bytes). Per-write timestamps are the design, so the client rule is one commit per editing pause, never per keystroke: at a 2 s cadence (about 10 edits) about 7x, at 20 s about 3x. Sizes in a foreign snapshot: a run about 20 bytes plus content, a segment about 4, a deleted range about 7, a commit table entry about 9.

Kept from tuning: deleted elements carry no content on the wire (182k → 6k runs), the per-delta commit table with bare indices (1–3 bytes per foreign stamp instead of 10), delta-coded table entries, runs spanning commits via segments, the shared delta stamp.

Accepted (tension 14): about 13 bytes per commit forever, so clients commit per editing pause. Stability-based GC (drop per-commit stamps once every writer acknowledged) would need every writer's frontier and stall on offline members, which the requirements forbid ("whether others are alive is never a protocol condition").

## Worked examples
Dots `a1`, `b3` (source letter, counter); stamps `(t, dot)`. Tests in `crdt-model/tests/props.rs` cite these.
- **Typing**: a at t=1 types `FOOBAR`: run `[1, 6, [0, [[0, 6]]], "FOOBAR", [], []]`. F=a1→HEAD, O₁=a2→a1, O₂=a3→a2, B=a4→a3, A=a5→a4, R=a6→a5.
- **Concurrent inserts at one anchor**: b at t=2 inserts `x` after O₂ (`[1, 1, [[1,3], [[0, 1]]], "x", [], []]`, sources `[a]`); c at t=3 inserts `y` after O₂. Children of O₂: y, x, B → FOOyxBAR.
- **Move with a concurrent insert**: from FOOBAR, b at t=2 inserts x after O₂ (x=b1→a3); a at t=3 moves FOO to the end: roots [F], pred HEAD, outside [B]. Writes B→HEAD (3,a7), F→R (3,a8). Read: BARFOOx.
- **Range with several roots**: abc built by inserting c, b, a at HEAD (t=1..3). Move `ab` after c (t=4): a→c, b→a. Read: cab.
- **Concurrent moves of one element**: from `abc`, a→c at t=5 and a→b at t=4. Read: bca; nothing duplicated.
- **Cycle**: from `acb` (a=a1→HEAD, c=a2→a1, b=a3→a2), B at t=5 moves a after b: c→HEAD (5,b1), a→b (5,b2); C at t=4 moves b after a: b→a (4,c1). Cycle a→b→a: b's edge (4) is oldest, b falls to prev (→c). Read: cba. Adjacent swaps do not cycle, since the mover re-anchors the outside successor to pred.
- **Reset against a newer insert**: from `abc` (t=1), A replaces with `xyz` at t=5 while B inserts `q` after b at t=6. a, b, c become bare anchors at END; q survives. Read: `xyzq` in either order. An insert at t=3 is dropped. `remove_aspect` at t=5 instead: absent until q arrives, then `q`.
- **Move displaces a concurrent insert**: from `abcd`, B at t=5 moves b to the end: c→a (5,b1), b→d (5,b2); C at t=4 inserts x after a. Children of a: c (5) before x (4). Read: `acdbx`; C intended `axcdb`. A move by position register cannot avoid rewriting the successor's anchor.
- **Delete vs move**: b deleted at t=4, moved after c at t=5. Read: ac; a later insert anchored at b appears after c.
- **Unknown anchor**: x arrives before FOOBAR: hidden until it arrives, even if FOOBAR was reset meanwhile.

## Research
- Loro's movable list and movable tree: production implementations of Kleppmann 2020 "Moving Elements in List CRDTs" and of tree cycle handling.
- Eg-walker (Gentle & Kleppmann 2024): op-based, but its text representation and size ideas transfer.
- Kleppmann & Beresford, "A Conflict-Free Replicated JSON Datatype": nested composition, key removal vs concurrent nested edit.
- Kleppmann & Brattli, "Undo and redo support for replicated registers and sets": matches dot-cancel undo.
- Almeida, Shoker, Baquero, "Delta State Replicated Data Types": the delta-state framework; its causal contexts are not used here.
