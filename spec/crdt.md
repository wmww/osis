# CRDT specification (v1 merge types)
> Summary: Exact state, wire delta grammar, join, read, ops, undo, un-merge and tombstone rules for every v1 merge encoding; the encoding lattice; chunking of large states; structural diff. Checked by the reference model in `crdt-model/`.

Status: draft 2026-10-16, derived from notes/crdt-sync.md and notes/versioning.md. Decisions made while writing are listed in §12 and mirrored in the notes. The byte layout of the commit header, blob framing and hashing live in the protocol spec (plans/protocol-spec.md); this document assumes only the header fields named in §2.4.

Goal: a second implementation reading this document converges byte-for-byte with the first on wire deltas (§3 canonical rules) and value-for-value on reads (§4, §5).

Notation: `[a, b]` is a CBOR array, `{k: v}` a CBOR map (int keys, sorted), `Opt(X) := [] | [X]`. `A < B` on stamps is the total order of §2.2. "Writer" is the node producing a delta, "reader" any node joining it.

## 1. Model

- An **aspect state** is a tree of **fragments**. Each fragment has a merge **encoding** (§3.1) that fixes its state shape, join and read. Nested fragments are self-describing, so join needs no schema.
- A **write** is the smallest unit of authorship: one register value, one element creation, one reset, one flag or position change. Every write carries a **stamp** (§2.2): the commit's timestamp plus the write's **dot**. Writes are never modified, only superseded (later stamp) or pruned (older than a reset).
- A **delta** is a fragment of the same grammar as a state. Applying a delta is `join`. Join is commutative, associative and idempotent, so delivery order, duplication and partial receipt do not matter.
- A **reset** is a stamp stored in a fragment or collection element; every write under it with a smaller stamp is dropped. It is the only removal mechanism (notes/crdt-sync.md).
- **Read** is a deterministic function from state to an osis value (notes/serialization.md). Apps see only reads.

## 2. Stamps, dots, sources, clock

### 2.1 Sources and dots
A **source** is who minted a run of counters:
- `Node(tid)`: a node's signing identity (15-byte tid). Counters are per (aspect, node), contiguous, starting at 1, never reused. A node that cannot be sure of its last counter for an aspect (restored from backup, lost state) must not write node-form dots for that aspect again; it uses commit form.
- `Commit(id)`: the commit itself (32-byte commit ID). Counters are per commit, contiguous from 1 across all the commit's deltas (aspects get disjoint ranges). The header marks the form once per commit; a commit uses one form for all its writes.
- `Derived(dot)`: synthetic, never written by any writer. Produced only by lattice embeddings (§7) that need several identities out of a single register write with dot `dot`. Counters start at 1. Belongs to the author of `dot` for attribution, frontiers and un-merge.

A **dot** is `(source, counter)`, counter ≥ 1. A dot identifies one write forever, and doubles as the identity of the element it created.

### 2.2 Timestamps and stamps
- `ts` is one unsigned integer: `wall_ms * 2^16 + logical`, `wall_ms < 2^47`. HLC rules: a node's clock is `max(wall clock, last ts seen) ` with `logical` incremented on equal `wall_ms`; on receiving a commit the clock advances to the commit's ts. A commit with `wall_ms(ts)` more than `MAX_DRIFT = 1 h` (format constant) ahead of the receiver's wall clock is **parked**: kept unjoined and counted as not received (frontiers, tombstone GC, §5.5) until local wall time catches up, then joined normally. So the clock never runs more than the cap ahead, and a node with a fast clock delays only its own writes (notes/constraints.md). The node tiebreak lives in the dot, not in `ts`.
- A **stamp** is `(ts, dot)`. One commit has one `ts`; every write in it has that `ts` and its own counter, so stamps inside a commit are ordered by counter, matching the writer's sequential intent.
- Total order on stamps: by `ts`; then source kind (`Node` < `Commit` < `Derived`); then source bytes (tid, commit ID; for `Derived`, the order of the underlying dot); then counter. Two different writes never compare equal.
- "Later wins" everywhere means this order. A clock-gaming writer wins; accepted (notes/constraints.md).

### 2.3 Counter consumption
A delta for one aspect gets the counter range `[lo, hi)` of its writer's source. Two kinds of writes:
- **Commit-level writes** share the stamp `(ts, source, lo)`, the **delta stamp**: register values, resets (fragment and element), deleted-flag writes, enum case writes, presence writes. One commit carries at most one such write per register, so they never need an order among themselves; against the commit's own reset they win by the `>=` rule (§4.2), which is the "reset, then content" shape of a replace.
- **Creations and position writes** each consume a fresh counter in op order, starting at `lo`: element creations (text/list element, set element, map entry, bag contribution) because the counter is the element's identity, and position writes because siblings written by one commit are ordered by counter (§6.1). The first creation of a commit shares counter `lo` with the delta stamp; the two are never compared (a creation is a different register from any commit-level write).
- `hi = max(lo + 1, last counter + 1)`: a delta with only commit-level writes still consumes one counter, so every commit sits inside its author's contiguous counter sequence and receipt frontiers (notes/permissions.md) cover it.
A reader checks that every own-source counter in a delta lies in `[lo, hi)` and that creations and position writes use distinct counters.

### 2.4 What the commit header provides
- `ts` of the commit.
- `sources` (the notes' "author table"): table of foreign sources referenced by the commit's deltas. Index 0 is the commit's own source (node form: the author node; commit form: this commit) and is not stored in the table. Entries: `Node` as a 15-byte string, `Commit` as a 32-byte string, `Derived` as `[src_index, counter]` (the referenced dot, whose source must itself be `Node` or `Commit`).
- Per delta: `(tid, ak, delta hash, counter range [lo, hi))` as in §2.3. Encoding IDs are inside the delta (§3.2), not in the header. The header also carries the writer's type hash and schema revision per delta (notes/versioning.md); merge ignores them.
- Dot form flag (node or commit).
- Snapshot marker (§8): a snapshot commit carries only foreign writes and consumes no counters (empty ranges).
- `expires: T` (wall ms), optional (§4.7).
- `undoes: commit id` for undo commits (§4.6).
Every other header field (author, actor, retention class, purge request, delete tokens, signature) is outside merge.

## 3. Wire grammar

All deltas and snapshots are osis canonical CBOR (notes/serialization.md): shortest heads, sorted map keys, no indefinite lengths, no null. A **delta** is `[nonce, Fragment]` with a 16-byte random nonce (no-fingerprint rule). The delta hash covers the whole array.

### 3.1 Encodings
| id | name | for schema types | read type |
|---|---|---|---|
| 0 | register | every scalar, tid, blob; default for int, float, string | the value |
| 1 | counter | int/float with `counter` knob | sum of live contributions |
| 2 | max | int/float `max` | max of live contributions |
| 3 | min | int/float `min` | min of live contributions |
| 4 | struct | struct | struct |
| 5 | enum | enum (incl. option, any) | enum |
| 6 | set | set | set |
| 7 | map | map | map |
| 8 | list | list<T> | list |
| 9 | text | string with `text`/`markdown` knob | string |

Unknown id (or an unknown nested id) parks the whole delta (notes/versioning.md). A parked delta is kept as bytes with its header tuple and re-examined after upgrade.

### 3.2 Grammar
```
Delta    := [nonce, Commits, Fragment]
Snapshot := [nonce, Commits, Fragment, Frontiers]   ; snapshot deltas, §8
Commits  := [[Src, [[dwall, logical, base]*]]*]   ; §3.3 rule 1
Ts       := uint                         ; §2.2
Src      := uint                         ; index into header sources, 0 = own
Ci       := uint                         ; commit index: 0 = this commit, i = Commits entry i (flattened)
Dot      := ctr | [Src, ctr]             ; ctr alone means own source
Stamp    := Ci | [Ci, ctr]               ; Ci alone means that commit's base counter (own: lo)
R        := Opt(Stamp)                   ; reset
W        := Opt(Stamp)                   ; explicit presence stamp, see §3.3
Anchor   := 0 | Dot                      ; 0 = HEAD (counters start at 1, so no clash)
Value    := any osis canonical value

Fragment := Register | Bag | Struct | Enum | Set | Map | Seq
Register := [0, R] | [0, R, Stamp] | [0, R, Stamp, Value]   ; [0, R, Stamp]: value-less write (§4.7)
Bag      := [1|2|3, R, W, [Elem*]]           ; Elem as in Set; the value register holds int|float
Struct   := [4, R, W, {field_id: Fragment}]
Enum     := [5, R, W, Case, {case_id: Fragment}]   Case := Opt([Stamp, case_id] | [Stamp])
Set      := [6, R, W, [Elem*]]               Elem  := [Dot, R, Opt(Fragment)]
Map      := [7, R, W, [Entry*]]              Entry := [Dot, R, Value, Opt(Fragment)] | [Dot, R, Opt(Fragment)]   ; Value is the key; omitted: key not carried
Seq      := [8|9, R, W, [Run*]]
Run      := [Dot, n, Creation, Content, [PosW*], [FlagW*]]
Creation := [] | [Anchor, [[Ci, k]*]]        ; segments: k consecutive elements created by commit Ci; sum k = n
Content  := text: string | []                ; list: [Fragment*] | []
PosW     := [i, Stamp, Anchor]               ; 0 <= i < n
FlagW    := [i_from, i_to, Stamp, bool]      ; inclusive range, 0 <= i_from <= i_to < n
```
**Commits** is the delta's table of every foreign commit whose stamps appear in the fragment (a commit is a `(ts, source)` pair). Entries are grouped by source in `Src` index order; within a group ascending by `ts`; `dwall` is the difference of `wall_ms` to the previous entry of the group (absolute for the first), `logical` the low 16 bits of `ts`, `base` the smallest counter of that commit's stamps in this delta. Commit index 0 is this commit `(header ts, own, lo)`. A stamp encodes as its commit index alone when its counter equals the commit's base, which is every commit-level write (§2.3) and the first creation.

**Run** semantics: a run describes elements `e_i` with dot `(first.source, first.ctr + i)`, `0 <= i < n`. With a `Creation`, the run **creates** them: segment `[Ci, k]` gives the next `k` elements the creation stamp `(ts(Ci), first.source, first.ctr + i)`; `e_0` anchors at `Anchor`, `e_i` (i > 0) at `e_{i-1}`. Without a `Creation` the run only carries writes on elements that exist elsewhere. `Content` lists, in order, the content of the run's elements that are **not deleted** after the run's `FlagW` are applied (text: one char each; list: one fragment each); deleted elements never carry content on the wire. `[]` means no content carried for any element (a pure flag or position delta, or, with a `Creation`, value-less creations, §4.7). `PosW` are position writes other than the creation write; `FlagW` are deleted-flag writes (§5.7).

Set elements have no key; their value is a `Register` fragment. A map entry's key is immutable and is repeated in every record of that entry (it is needed to resurrect an entry whose tombstone has lost it, §5.6), except tombstones and entries whose creation is value-less (§4.7), which use the keyless form.

### 3.3 Canonical rules (byte-for-byte determinism)
1. Header `sources` lists foreign sources in order of first appearance in the canonical encoding (a `Derived` source is preceded by its underlying source). `Commits` holds exactly the foreign commits with stamps in the fragment, grouped and ordered as in §3.2, each with `base` = its smallest counter in this delta. A `Dot` or `Stamp` uses the bare form whenever it can.
2. Arrays of elements, entries, runs are sorted by dot (source as in §2.2, then counter). `PosW` sorted by `(i, Stamp)`, `FlagW` by `(i_from, Stamp)`; segments in element order with adjacent equal `Ci` merged. Maps sort by canonical key bytes as all osis maps do.
3. Runs are maximal. A creation run extends over consecutive dots of one source as long as each element's creation write exists in the state, `e_i` was created anchored at `e_{i-1}`, and "carries something" (is deleted, or has content) is the same for all. A non-creation run extends over consecutive dots that all have no creation write, no position writes, the same deleted write, and the same "carries something".
4. `W` is encoded iff the fragment's presence stamp (§4.3) is greater than every stamp carried inside the fragment that counts toward presence, or the fragment carries no write at all. Otherwise `[]`.
5. A fragment never carries writes already implied by another write in the same delta (e.g. a creation run does not list its creation position writes in `PosW`), and a snapshot never carries content for deleted elements.
6. Own-source counters lie in the header range; creations and position writes have distinct counters (§2.3).
7. A reader rejects a delta (bad input, never a panic) if: non-canonical CBOR; a `Src`, `Ci` or counter is out of range or 0 where 1 is the minimum; a non-canonical table order or bare/array form; a segment's commit has another source than the run; n = 0; a `FlagW` or `PosW` index out of range; a non-empty `Content` whose length differs from the number of non-deleted elements of the run; a `Register` with a reset below a nested level (only aspect roots carry one).

## 4. Join, prune, presence (all encodings)

### 4.1 Join
`join(A, B)` where both are the same encoding: take the union of all writes, keeping for each register the write with the greatest stamp, for each reset the greatest stamp, for each collection the union of elements by dot (joining records of one dot recursively), then **prune** (§4.2). Different encodings: §7. Join of a state with a delta is the same operation; a state is just a fragment with every stamp written in full.

The union of two sets of writes with per-register maximum is a join-semilattice; prune is a closure operator that commutes with it (a write dropped by a reset would be dropped by the same reset after any later join). Hence commutativity, associativity, idempotence. The reference model checks this by property tests (§10).

### 4.2 Prune
Every fragment has an **effective reset** `E = max(E_parent, own R)`, with `E_root = own R` and `-inf` where none. A write with stamp `s` survives iff `s >= E`. Equality means the write and the reset come from the same commit (a replace: reset and content share the delta stamp, §2.3; embeddings §7 do the same), and then the content wins. Rules per structure:
- Registers: the write is dropped if `s < E`.
- Composites: the presence stamp (§4.3) is dropped if `< E`; children are pruned with `E` as their parent reset.
- Collection elements: the element's own `R` survives iff `>= E_parent`; its content is pruned with `E_elem = max(E_parent, R_elem)`. An element record whose content is entirely pruned and whose own `R` is dropped is removed from the state. One whose content is pruned but whose `R` survives is a **tombstone** (dot plus reset stamp, nothing else). Seq elements additionally keep their record (as an anchor) as long as any position or flag write survives.
- A delta, after pruning against the state it joins, may contribute nothing. That is normal.

### 4.3 Presence
- A register is present iff it holds a surviving write.
- A composite (bag, struct, enum, set, map, seq) carries a **presence stamp** `written` = the greatest stamp among all writes inside it (its children's writes, element creations, element resets, nested resets, case writes, position and flag writes), excluding its own reset and value-less writes (§4.7), plus any explicit `W` write. It is present iff `written` survives (`written >= E`). This makes an explicitly written empty collection present, and a collection emptied by removals present (the removal is a write inside it), while `remove_aspect` (reset with nothing after) makes it absent.
- An aspect is present on a thing iff its root fragment is present. `/aspects` reads the present ones.
- A writer emits an explicit `W` (consuming a counter) only when creating or replacing a composite with no content writes in the same delta (an empty set, an empty struct). `W` is a write like any other for frontiers and un-merge.

### 4.4 Read
Defined per encoding in §5. Reading a fragment that is not present yields "absent"; inside a struct that is a missing field (reader default or typed-read error, notes/versioning.md); inside a map entry or list element it means the element is not live.

### 4.5 Writes an op produces; a commit is a net effect
Local ops are resolved against local state at write time (index paths, keys, values become dots) and produce one delta per touched aspect; sections 5.x list each op's writes. Resolving against local state is what makes removals name only observed dots (add-wins against unseen adds, notes/crdt-sync.md).

A delta is a state fragment, so a commit carries the **net effect** of the ops batched into it, not their history: a register written twice carries the last value; all deletions of one commit are one flag write (the delta stamp); an element created and removed within the same commit is omitted, and elements that were chained to it are created anchored where it was (their stamps do not change). Nothing outside the commit can have observed the omitted writes, so this is invisible. It matters for size: §11.

### 4.6 Undo (cancel per dot) and un-merge (by author)
Undo is a new commit with `undoes` set; its deltas are ordinary writes chosen per original write:
- element creation (text/list insert, set add, map put, contribution): text/list → deleted-flag write `true` on the dot (keeps the anchor; §5.7); set/map/bag → element reset on that dot.
- register write, case write, position write: write the previous value only if the undone write is still the current winner locally; otherwise no write.
- flag write, element reset (delete, set remove, key remove): the inverse write (flag `false`, or re-add) carrying content from the undo buffer, at the undo commit's stamp.
- fragment reset (remove_aspect, replace, enum case change): re-insert the pre-reset value from the undo buffer with fresh dots (`replace`).
Purged or expired originals are not undoable. Redo = undo of the undo commit.

**Un-merge** (revocation, notes/permissions.md): remove every write whose dot's source belongs to the invalid author (`Derived` dots count for the author of the underlying dot) from the state, then re-derive registers' winners, `written`, pos top-2 (§5.7) from the remaining writes. Seq elements created by the author keep their record with their creation position as a content-less, hidden anchor. Position registers keep only two writes (§5.7), so un-merging the current one may expose a position older than the one a full history would give; accepted. Register values the author overwrote are restored from own retained bodies or peers, else lost (notes/permissions.md).

### 4.7 Expiry and value-less writes
A commit with `expires: T` (header, `T > wall_ms(ts)`, else the commit is rejected) owns, in each aspect, the writes of its source with a counter in its range (commit form: every write of its source). Its **value-carrying** writes are register values, enum case writes, set and bag element values, map entry creations (the key is the creation's value) and sequence element creations (the text char or list element). Its other writes (resets, `W`, deleted flags, position writes) carry no app data.

- **Value-less writes.** A value-carrying write may be held without its value: stamp kept, value gone. Join: the copy with the value wins over the copy without (copies of one write always carry the same value), so the lattice is unchanged. A value-less write takes part in "later wins" like any other but reads as absent: a register whose winner is value-less is absent; an enum whose case winner is value-less is absent and its payloads stay hidden until a reset sweeps them (as D7); a set or bag element, map entry or sequence element whose creation is value-less is not live, and any nested writes it has stay hidden until a reset sweeps them (the entry's key is not stored, and a key repeated in another record is ignored). A sequence element with a value-less creation is the same hidden anchor un-merge leaves (§4.6). Value-less writes do not count toward `written` (§4.3).
- **Expiry rule.** Once a node's wall clock reaches T it holds every value-carrying write of the commit value-less, and strips the value from any copy that arrives later (an undelete repeating the content, a stale peer, another projection); it knows T from the commit header, which outlives the body. Its non-value writes stay. Expired bodies and every local reference to them are then dropped under the purge rules (notes/crdt-sync.md).
- Why this converges: expiry changes no stamp and no ordering, only whether a value is known, so it commutes with join and with arrival order. A late write older than the expired one still loses to it; a newer one wins. Dropping the commit's resets instead would let content they pruned on one node survive on a node that received it after T. Not taken: a floor at T on a register whose winner expired (notes, review 2026-10-16). Applied only when the expired write is the current winner, it diverges: a write stamped between the commit and T wins on nodes that received it before T and loses on the others. Applied to every register the commit wrote, it expires other authors' newer writes.
- A commit writing inside an element created by an expiring commit (a reaction to a disappearing message) repeats its key or anchors to it; the Mutator gives such a commit an expiry no later than T by default.
- Snapshots carry the commit's value-carrying writes value-less, before and after T, and do not retire it, so its content lives only in its own blob, which blind nodes drop at T (§8). Before T a node holding the snapshot but not yet the commit reads those writes as absent, like any partial receipt.

## 5. Encodings

Each encoding below gives: state, delta shape (= grammar of §3.2, restated where helpful), join specifics beyond §4.1, read, ops, tombstones. Notation for op deltas: `D` is the delta stamp (bare `0` on the wire), `k, k+1, …` fresh counters (§2.3).

### 5.1 Register (0)
- State: `R`, optional write `(stamp, value)`. Nested registers (struct fields, enum payload leaves, set element values) never carry their own `R` (always `[]`); only an aspect whose root is a register uses it.
- Join: greater stamp wins. Prune per §4.2.
- Read: the value.
- Ops: `set v` → `[0, [], D, v]` = `[0, [], 0, v]`. `remove_aspect` (root) → `[0, [D]]`. `replace v` (root) → `[0, [D], D, v]` (reset and content share the delta stamp; content wins by `>=`).
- Undo of a write: previous value if still winner (§4.6).
- Tombstones: none; the reset stamp is the whole removed state.

### 5.2 Bags: counter (1), max (2), min (3)
- State: `R`, `written`, elements `{dot: (R_elem, value register)}` exactly as a set (§5.5); the register holds the contribution amount (int or float per the aspect type). The register's first write has the element's creation stamp.
- Join: as set; prune.
- Read: counter = sum of live contributions (i64 saturating, never a panic); max/min = the extreme of live contributions. Absent when nothing is live and `written` does not survive.
- Ops: `inc(a)` → one element `[k, [], [[0, [], D, a]]]`. `set v` (a replace) → fragment reset `D` then one element `k`. For max/min a bare contribution is "observe v".
- Undo of a contribution = element reset on its dot (cancel per dot, idempotent when two devices undo the same inc). Undo of a `set` = replace with the pre-reset contributions from the undo buffer, fresh dots.
- Tombstones: as set elements (§5.5). GC: an implementation may additionally drop, for max/min, every element of a source that is not that source's extreme, and for counters fold a source's contributions that are all older than the newest received frontier into one record per source only if it also keeps the dot set for un-merge; the model does neither.

### 5.3 Struct (4)
- State: `R`, `written`, `{field_id: fragment}`. Field IDs are the schema's wire IDs; unknown IDs are kept and joined like any other.
- Join: per field; prune.
- Read: struct with every present field. Missing fields are the reader's problem (defaults, notes/versioning.md). An unknown field ID is read as data (`Value` API) and ignored by typed reads.
- Ops: `set_field(id, v)` → `[4, [], [], {id: diff-delta of v against the field's local state}]` (structural diff §9, so a field of composite type gets nested writes). `replace` of the struct → `[4, [D], [], {id: fragment of each field}]`; a struct with no fields → `[4, [D], [D], {}]`.
- Tombstones: none beyond `R`.

### 5.4 Enum (5)
- State: `R`, `written`, case register `(stamp, case_id)`, payloads `{case_id: fragment}`. Payload writes are filed under the case they were made for; the payload of a case that is not current stays in the state, hidden, until a reset sweeps it.
- Join: case register by stamp; payloads per case; prune (payloads of a non-current case are pruned by `E` like any other fragment, so a case change, which is a reset, drops every older payload write of every case).
- Read: `[case_id]` or `[case_id, read(payloads[case_id])]`. A payload fragment that is absent for a case that has a payload type is a typed-read error (missing payload), never a panic. If the case register is absent the enum is absent, whatever payloads exist.
- Ops: `set_case(id, payload)` where id differs from the current case → `[5, [D], [], [[D, id]], {id: payload fragment}]` (reset, case write, payload). Same case with a changed payload → `[5, [], [], [], {id: diff-delta}]` (no case write). `option<T>`: `none` is a case without payload: `[5, [D], [], [[D, 0]], {}]`.
- Why a nested payload write never changes the case (D7): a writer editing a field of case A while a concurrent writer switched to case B must not flip the enum back to A with a half-written payload; the newer field write is kept hidden and is swept by the next reset.

### 5.5 Set (6)
- State: `R`, `written`, elements `{dot: (R_elem, value register)}`. The value register's first write has the element's creation stamp.
- Join: union by dot; per element `R` max and register max; prune (§4.2). A tombstone is `(dot, R_elem)`.
- Read: the set of distinct values of live elements (live = register present under `E_elem`). Equal values from several elements read once. Large values compare by keyed content hash (notes/data-model.md).
- Ops (resolved locally): `add v`: if an element with value v is live locally, no write; else `[6, [], [], [[k, [], [[0, [], D, v]]]]]`. `remove v`: for every live local element with value v a record `[dot, [D], []]`; all removed elements share the one reset stamp `D`. `replace {v1..}` → fragment reset `D`, then adds with fresh counters.
- Tombstone lifetime: `(dot, R_elem)` may be dropped once the node has applied the commit that created `dot` (known from received dot ranges) and the commit carrying the reset: nothing but a causally later undo can target the dot, and an undo's stamp is later than the reset. Until then the tombstone is needed to drop a late-arriving older add. Parked commits count as not applied.

### 5.6 Map (7)
- State: `R`, `written`, entries `{dot: (R_entry, key, fragment)}`, plus a local index `key -> live dots` (not part of the lattice). The key is immutable and repeated in every record of the entry on the wire.
- Join: union by dot; per entry `R` max, fragment join; prune. Tombstone = `(dot, R_entry)`; the key is dropped with the content (content-free tombstone).
- Read: for each key with at least one live entry, `read(join of the live entries' fragments)`. Two live entries with one key (concurrent puts) read as one merged value.
- Ops: `put(key, v)`: if a live entry with that key exists, write `v` by structural diff into the **lowest live dot** (lowest in §2.2 dot order) and leave the others alone; else create `[k, [], key, [fragment of v]]`. `remove(key)`: the reset stamp `D` on every live dot with that key, records `[dot, [D], key, []]`. `set_field` and other path ops into an entry go to the lowest live dot. `replace` of the map: fragment reset then puts.
- Resurrection (D8): a nested write newer than the entry's reset makes the entry live again holding only the surviving writes; the record carries the key so the reader can index it. An older nested write is dropped by the tombstone. This is why map tombstones live **until the map fragment is reset** (then every tombstone older than the reset is itself pruned). No other GC in v1.
- Why not merge same-key entries into one: the dots are different authors' identities; joining their contents at read time gives the same value with no state rewrite.

### 5.7 Sequences: list (8) and text (9)
Text is `list<char>` with run compression and immutable element content; list elements carry a recursive fragment.

**State** per element (identity = creation dot):
- `created`: the creation write `(stamp, anchor)`, kept as long as it survives pruning even when two later moves have pushed it out of `pos`. Text content has no stamp of its own: it is present iff `created` is.
- `content`: text: the char, immutable (an implementation may drop it locally once the element is deleted; a later undelete delta or a specific-blob fetch restores it). List: a fragment, joined like any other.
- `pos`: the two greatest position writes `(stamp, anchor)` seen (top-2 under §2.2), the creation write included: `cur` and `prev`. Top-2 of a union is the top-2 of the union of top-2s, so this is a lattice.
- `deleted`: LWW register of bool; absent means false. Its writes may cover ranges (`FlagW`).
- Element existence: a record survives while `created`, a position write or a flag write survives pruning (§4.2); otherwise it is dropped entirely, which also hides anything anchored to it until the next reset sweeps that too.

**Join**: union by dot; `created` and text content: first seen (all copies are equal); list fragment join; pos: top-2 of union; deleted: max stamp; prune.

**Read**: the linearization (§6) of elements that are not deleted and have content, mapped to their content (text: concatenated string; list: list of `read(fragment)`, skipping elements whose fragment is absent).

**Ops** (all resolved against local state; index paths never go on the wire):
- `insert(after: index|HEAD, items)`: one creation run `[k, n, [anchor, [[0, n]]], content, [], []]`, anchor = dot of the element visually at `index` (HEAD for 0). Elements get dots `k..k+n`.
- `delete(range)`: for each maximal run of consecutive dots in the range, a record `[first, m, [], [], [], [[0, m-1, D, true]]]`; the one delta stamp for the whole commit. Content of the deleted elements may be dropped locally.
- `undelete(dots)`: same with `false`, content carried in `Content` (from the undo buffer or clipboard) so readers that dropped it recover it.
- The **range** of a delete or move is the slice of the full placement order (deleted elements included, §6.1) from the first to the last visible element of the selection, so hidden anchors inside a selection travel with it; trailing deleted elements stay behind.
- `move(range, after: index|HEAD)`: let `roots` be the elements of the range whose chosen parent (§6.2) is outside the range, in visual order; `pred` the visible element before the range (or HEAD); `outside` the elements outside the range whose chosen parent is inside it, in visual order (typically the subtree roots of the range's successors). Writes, each consuming a counter: first the `outside` elements **in reverse visual order**, each a position write to `pred` (reverse, because siblings read greatest-first: the one written last lands nearest `pred`); then root 1 to the destination anchor; then root j>1 to the last element, in placement order, of root j-1's moved subtree (its subtree minus the `outside` subtrees). Interior elements of the range are never rewritten (rewriting would change their sibling keys and reorder concurrent neighbours).
- `cut` = delete range (client remembers the dot ranges beside the clipboard text); `paste` = `move` of the remembered roots to the destination + `undelete` of the range when the clipboard still matches the remembered ranges, else a plain insert. The protocol has no clipboard concept.
- List element edits: `set_field`/nested ops on element i → record `[dot, 1, [], [nested fragment], [], []]`.
- `replace(items)`: fragment reset `D`, then a creation run. Old elements survive only as records if they have writes `>= D` (none, normally), so a replace also forgets every anchor; concurrent inserts into the old content are hidden and swept.

**Undo**: insert → delete flag; delete → undelete with content; move → position write back to the pre-move anchor if the undone write is still `cur`. Delete and move resolve independently: a moved-and-deleted element is a hidden anchor at its new place.

**Tombstones**: a deleted element keeps its record (dot, pos top-2, deleted) forever within the aspect's current reset epoch; it is 3–4 bytes in a run-compressed snapshot. No tombstone compaction in v1 (notes/crdt-sync.md).

**Size**: a snapshot of a text is its runs (§3.2). In a foreign snapshot a run costs about 20 bytes plus content, a segment (one commit's stretch of a run) about 4, a deleted range about 7, a commit table entry about 9. The benchmark in §11 measures this on a real trace.

## 6. Linearization

A deterministic function of state. Correctness never depends on it (convergence is by join); it only decides what users see.

### 6.1 Tree and order
- Every element has an **anchor**: `HEAD` or another element's dot. Children of X are the elements whose chosen position write (§6.2) anchors at X, ordered by that write's stamp, **greatest first** (RGA: a newer insert at the same anchor goes nearer the anchor; a moved element lands directly after its target, ahead of the target's older children).
- The order is the depth-first traversal from HEAD: X, then each child subtree in sibling order. Deleted elements and elements without content are traversed (their children are placed) but not emitted.
- An element whose chosen anchor is not in the state (its creation has not arrived, or it was swept by a reset) is **hidden** with its whole subtree until the anchor arrives.

### 6.2 Choosing a position: cycles
Position writes are rewritten only by moves, so a cycle in the anchor graph contains at least one move edge. Algorithm, run on the whole state (incremental implementations must produce the same result):
1. Every element starts on candidate 0: `cur`. Candidates after that: `prev` (if any), then `END`.
2. While the anchor graph (over elements with a known anchor) has a cycle: among the cycle's elements, demote the one whose **current edge has the smallest stamp** and that still has a next candidate; if none has one (every element of the cycle is already on `prev` with no `END` reached — impossible since `END` is always available, so this case does not arise).
3. An element on `END` anchors at HEAD with a virtual stamp below every real stamp, ordered among `END` elements by dot ascending; it therefore appears after every real top-level subtree, at the end of the sequence, with its subtree. An element whose `prev` anchor is unknown skips to `END`.
Rationale: the oldest move in a cycle is the one the other movers did not know about; demoting it keeps the most recent intention. Falling back twice only happens with three or more concurrent moves over the same elements; placing the remainder at the end keeps content visible instead of hiding it.

### 6.3 Incremental evaluation
Cache the linear order and the tree. A delta touching k elements re-places those k subtrees; a delta introducing a position write that creates a cycle recomputes §6.2 for the strongly connected component only. Not normative.

### 6.4 Worked examples
Dots are written `a1`, `b3` (source letter, counter); stamps `(t, dot)` with `t` the ts.

**Typing**: node a at t=1 types `FOOBAR`: run `[1, 6, [0, [[0, 6]]], "FOOBAR", [], []]`. Elements F=a1→HEAD, O₁=a2→a1, O₂=a3→a2, B=a4→a3, A=a5→a4, R=a6→a5. Linearization: FOOBAR.

**Concurrent inserts at one anchor**: b at t=2 inserts `x` after O₂: `[1, 1, [[1,3], [[0, 1]]], "x", [], []]` with sources table `[a]` (index 1). c at t=3 inserts `y` after O₂. Children of O₂: y (t=3), x (t=2), B (t=1) → FOOyxBAR. RGA: later insert nearer the anchor.

**Move with a concurrent insert (the FOOBAR case)**: from FOOBAR, b at t=2 inserts x after O₂ (x=b1→a3). a at t=3 moves FOO to the end (after R): range [F, O₁, O₂], roots = [F] (O₁, O₂ have parents inside), `pred` = HEAD, outside elements anchored inside = [B (a4→a3)]. Writes: B→HEAD stamp (3,a7); F→R stamp (3,a8). Tree: HEAD children: B (3,a7) then nothing else (F moved); B→A→R→F (3,a8); F→O₁→O₂→{x (2,b1)}. Linearization: BARFOOx. Convergent on both nodes.

**Range with several roots**: c (t=1) inserts c→HEAD, then b→HEAD (t=2), a→HEAD (t=3): abc. Move `ab` to after c (t=4): roots [a, b] (both anchored at HEAD); pred=HEAD; no outside elements. Writes: a→c (4,·), b→DFS-last(a)=a (4,·). Result: c a b.

**Concurrent moves of one element**: from `abc`, b moves a after c at t=5 (a→c), c moves a after b at t=4 (a→b). a's pos: cur=(5,c), prev=(4,b). Read: b c a. The later move wins; nothing is duplicated.

**Cycle**: from `xy` (y=a2→a1, x=a1→HEAD), b at t=5 moves x after y: outside elements anchored inside [x]: y → pred=HEAD (5,b1); x→y (5,b2). Concurrently c at t=4 moves y after x: y's outside children: none (y is a leaf); y→x (4,c1), but y's creation anchor was already x, so that write is redundant yet legal. Join: x: cur=(5,b2)→y, prev=(1,a1)→HEAD; y: cur=(5,b1)→HEAD, prev=(4,c1)→x. No cycle: y x. Now suppose instead c had moved y to after x's **successor** z in `xzy`...: cycles need every element on the cycle to have been moved concurrently; e.g. x→y (5), y→x (4): demote the smallest-stamp edge on the cycle, y (4) → y falls to `prev`; result x y with y after x, i.e. the t=5 intention.

**Delete vs move**: from `abc`, b deletes b at t=4 (flag), c moves b after c at t=5. State: b.deleted=true (4), b.pos cur=(5,·)→c. Read: a c. A later insert anchored at b appears after c.

**Unknown anchor**: a reader receives b's `x` before a's `FOOBAR`: x's anchor a3 unknown → hidden. After a's commit arrives it appears. If a's run had been replaced (reset) before x arrived, x is hidden until the next reset prunes it.

## 7. Lattice embeddings

`join(A, B)` with encodings `eA != eB`:
1. If there is an edge `eA -> eB` (A is the poorer side), replace A by `embed(A)` and join normally; symmetric for `eB -> eA`. The result's encoding is the richer one; a stored state therefore ends up in the greatest encoding seen (the schema's encoding is a minimum, notes/versioning.md).
2. Otherwise (no edge in either direction): let `wA`, `wB` be each side's greatest stamp (including its reset). The side with the greater one is kept; the other contributes only a reset at its own greatest stamp. So `join = prune(keep with R = max(R_keep, w_loser))`. Deterministic and commutative; associativity is checked by the model.

Edges (all from register, by value type):
| edge | condition | embed(register {R: r, write (s, v)}) |
|---|---|---|
| register → counter | v is int or float | `[1, max(r, s), s, [[s, v]]]`: reset at s, one contribution at s |
| register → max | int/float | same shape, encoding 2 |
| register → min | int/float | same shape, encoding 3 |
| register → text | v is string | `[9, max(r, s), s, runs]`: elements with dots `(Derived(s.dot), i+1)` for the i-th char, all stamps `(s.ts, Derived(s.dot), i+1)`, chained from HEAD, content = the chars |
A register with no write embeds as `[enc, r, [], ...]` (reset only). A register whose value has the wrong type for the edge (a bool joined with a counter) uses rule 2.

Why content at the reset's stamp survives: prune keeps `>=` (§4.2); the embedding reset is `(s.ts, s.dot)` and the contributions and text elements compare greater (same ts, same dot for bags, since they are the same write; `Derived` sorts after `Node`/`Commit` for text). Consequences, intended: an old app saving a string wipes text edits that were concurrent and older, and keeps those newer (its save is one LWW write); an old app saving an int replaces the counter total. `Derived` dots never go on the wire from a writer, but a new-app insert anchored to an embedded char references `(Derived(s.dot), i)` through the header sources table (§2.4), and a snapshot of such a text carries them.

No other edges in v1: struct, enum, set, map, list have exactly one encoding each; a type change is a transition to a new item (notes/versioning.md).

## 8. Large states (paging and chunked snapshots)

Principle: state and snapshots are the same grammar, so a snapshot of a chunked state is a fragment whose collection arrays may be replaced by links to **pages**.

- Grammar extension: in `Bag`, `Set`, `Map`, `Seq`, the element array may be `[Link*]` (each a LINK-tagged value, notes/serialization.md) instead of `[Elem*]`; a page blob is a canonical CBOR array of elements (`[Elem*]`, `[Entry*]`, `[Run*]`), or again `[Link*]` (at most 2 levels: a root of links to pages of links to pages). A fragment is paged iff its element array as plain CBOR would exceed `PAGE_TARGET = 64 KiB`; a paged array is split into pages at content-defined boundaries over the canonical bytes of consecutive elements (gear hash, average 64 KiB, min 16 KiB, max 256 KiB; parameters shared with notes/serialization.md once fixed there), so equal element runs give equal page blobs regardless of history. Canonical: paging is mandatory above the threshold and forbidden below, so two nodes snapshotting identical states produce identical bytes. Pages are blobs under random keys like chunks (notes/local-store.md).
- Join of a snapshot with links: the reader fetches pages (lazily by policy, notes/sync.md) and joins their elements; a page's elements are all keyed by dot, so pages can be joined independently.
- Local store units (notes/local-store.md, Open): an implementation pages large states the same way internally, one unit per page plus an index unit (`key -> page`, `dot range -> page`, for text also `dot -> linear position` caches). A purge of one entry rewrites one page. Not normative.
- Text: run records are already paged in dot order; linearization needs all pages, so very long texts (tens of MB) load fully for read. Acceptable for v1; a tree index (counts per subtree) is a later optimization.
- **Snapshot deltas** are `[nonce, Commits, Fragment, Frontiers]` with `Frontiers := [[Src, ctr]*]`, sorted by `Src`, one entry per `Node` source with `ctr` ≥ 1 the largest counter such that the writer has applied all of that node's writes in this aspect up to it (parked commits are not applied, §2.2). The fragment reflects every write in those ranges; a receiver adds `[1, ctr]` to its received-dot ranges for (aspect, node), which closes them for set tombstone GC (§5.5), receipt logs and the backfill rule (notes/permissions.md), and learns the node's tid from the header `sources` table (frontier sources count for §3.3 rule 1, after the fragment). `Commit` sources have no frontier: a receiver keeps a snapshot's commit-form set tombstones until a reset sweeps them. A snapshot commit carries no writes of its own and consumes no counters (§2.4).
- Snapshots never carry the values of writes from commits with an expiry, expired or not (§4.7): those writes go value-less and their commits are not retired. Content of `purge`-class commits that is still live is carried as usual.
- Deltas (non-snapshot) are never paged; a writer producing a delta above `PAGE_TARGET` (bulk import) may split it over several commits.

## 9. Structural diff (`set_aspect` default)

Input: local state fragment `S` (may be absent) and new value `v`. Output: writes, as a delta. Rules per encoding, recursive:
- register: write iff `read(S) != v` (bit-exact for floats, notes/serialization.md) or S absent.
- bag: counter: `inc(v - read(S))` if different; max/min: reset + contribution if `v != read(S)` (a max cannot go down otherwise).
- struct: per field of `v`: recurse into `S.fields[id]`. Fields present in S but not in `v` are left alone (open structs: the writer only knows its fields; a typed `v` always has all the writer's fields).
- enum: same case → recurse into the payload; different case → `set_case`.
- set: adds for values in `v` not live in S; removes for live values not in `v` (one reset stamp).
- map: keys only in `v` → put; keys only in S → remove; both → recurse into the lowest live entry.
- list: LCS (Myers) over elements with equality = `read(elem) == item` (deep); unmatched old elements and new items are then **paired in order** while both remain and recursed into (a changed entry is an edit, not delete+insert); leftover old → delete, leftover new → insert after the preceding matched/paired element. Caveat kept from the notes: a changed entry that the pairing misaligns becomes delete+insert and loses concurrent edits; apps editing list entries concurrently should use path ops.
- text: Myers diff over chars → deletes and inserts (no move detection). Equal strings → no writes.
- absent S: everything is a creation; composites with no content get an explicit `W`.
`set_aspect_replace` ignores S: fragment reset then the writes of a diff against absent.

## 10. Reference model

`crdt-model/` is a small, slow, obviously-correct Rust implementation of this spec: `State` (the abstract lattice with fully resolved stamps), `join`, `prune`, `read`, the ops of §5, un-merge, the §3 encoder/decoder (own minimal canonical CBOR subset), the §7 embeddings and the §9 diff. Property tests (proptest):
- convergence: random op sets from several writers, deltas delivered in random orders with duplication and omission of prefixes, all nodes read equal values and have equal encoded states;
- join is commutative, associative, idempotent on random states;
- single writer: a sequential model (a plain `Vec<char>`/`Vec<Value>`, `BTreeMap`, etc.) matches reads after every op;
- encode→decode round trip is identity and re-encode is byte-identical; the decoder never panics on random bytes and on mutated valid deltas;
- embeddings commute with join: `embed(join(a,b)) == join(embed(a), embed(b))` for register pairs, and joining a register delta into a text state equals joining its embedding;
- undo: `join(s, undo(d)) ` reads like the state without `d` for the single-writer case;
- diff: `read(join(S, diff(S, v))) == v`.
The model is not the implementation; the implementation is tested against it. Not yet modeled: value-less writes and expiry (§4.7), snapshot frontiers (§8) (issues/crdt-model-expiry.md).

## 11. Text size benchmark
Target (notes/crdt-sync.md): encoded text snapshot between 1.5x and 3x the plain text on Kleppmann's automerge-paper editing trace (259,778 single-character edits, final text 104,852 bytes, 182k elements of which 77k deleted). `crdt-model/src/bin/text_bench.rs` replays the trace as one writer with realistic wall-clock timestamps (2 s per commit), commits the net effect per batch (§4.5), and encodes the state as a foreign node's snapshot (every stamp through the commit table).

| edits per commit | commits | commit table | runs | flag writes | snapshot | ratio |
|---|---|---|---|---|---|---|
| 1 | 259,778 | 2.47 MB | 6,288 | 77,463 | 4.64 MB | 44x |
| 10 | 25,931 | 243 KB | 6,062 | 12,721 | 687 KB | 6.6x |
| 100 | 2,598 | 24 KB | 6,000 | 5,431 | 331 KB | 3.2x |

Reading: the content is 105 KB and the run records about 150 KB (6,000 runs, 25 bytes each, the floor for this trace's edit pattern); everything else is proportional to the number of **commits** (about 9 bytes of commit table plus 4 bytes of run segment each) and of **deleting commits** (about 8 bytes each). Per-write timestamps are the design (one conflict rule everywhere), so this cannot be compressed away; what decides state size is how many commits a client makes. The 1.5–3x target is met only at roughly 100 edits per commit. Decision D12 records the consequence: clients batch edits into one commit per pause (a few seconds), never one per keystroke; at a 2 s cadence (about 10 edits) the state is about 7x the text, at a 20 s cadence about 3x. Still open for the owner: whether that is acceptable or stability-based GC should come forward (notes/crdt-sync.md).

What was tried and kept: deleted elements never carry content on the wire (runs no longer split at deletions: 182k → 6k runs), the per-delta commit table with bare commit indices for commit-level writes (a foreign stamp costs 1–3 bytes instead of 10), delta-coded commit table entries, runs spanning commits via segments, and the delta stamp shared by all commit-level writes (so a backspace burst in one commit is one flag write). Rejected: columnar/bit-packed encodings (not worth leaving CBOR for a 20–30% gain), dropping stamps from deletions (changes undo semantics, and deletions are no longer the dominant cost).

## 12. Decisions made while writing (mirrored in notes/crdt-sync.md)
- **D1 HLC tiebreak lives in the dot.** `ts` is `wall_ms * 2^16 + logical`; the node tiebreak of the notes' HLC is the stamp's source, which also works for commit-form dots where the source is the commit ID (not knowable before signing). §2.2.
- **D2 Delta stamp.** Commit-level writes share one stamp `(ts, source, lo)`; only creations and position writes consume counters. Removes 3–6 bytes per write and most intra-commit ordering questions; frontiers still cover every commit because a delta always consumes at least one counter. §2.3.
- **D3 `>=` survival.** A write survives a reset iff its stamp is not smaller. Lets a replace and the embeddings (§7) put content at the reset's own stamp.
- **D4 Presence stamp `written`.** Composites are present iff the greatest stamp inside them (or an explicit presence write) survives; this is how an explicitly empty set or struct exists and how a collection emptied by removals stays present. §4.3.
- **D5 Derived sources.** The register → text embedding needs one identity per character out of a single write; `Derived(dot)` sources provide them without a third dot form. §2.1, §7.
- **D6 Bag contributions are set elements.** Counter/max/min reuse the set element shape; undo of an increment is an element reset (idempotent across devices). §5.2.
- **D7 Enum payloads are filed per case.** A nested payload write never changes the case; a payload of a non-current case stays hidden until a reset sweeps it. §5.4.
- **D8 Map tombstones live until the map is reset; set tombstones until both commits are applied.** §5.5, §5.6.
- **D9 Undo of a text/list insert is a deleted-flag write**, not an element reset (keeps the anchor). The notes said "reset that dot"; for sequences the flag is strictly better. §4.6.
- **D10 Cycle breaking: demote the smallest-stamp move edge; after `cur` and `prev`, an element goes to the end of the sequence** rather than being hidden. §6.2.
- **D11 Sequence elements keep their creation write separately** from the top-2 position slots (needed to encode runs and to tie text content to a stamp). §5.7.
- **D12 Commit batching is a client rule**: one commit per editing pause (seconds), never per keystroke; a commit carries the net effect of its batch. §4.5, §11.
- **D13 Encoding IDs live in the delta, not in the header tuple.** The protocol spec's header carries `(tid, ak, hash, lo, hi)`. §2.4.
- **D14 Move range spans deleted elements inside the selection; outside subtrees are re-anchored in reverse visual order.** Found by the model's sequential test. §5.7.
- **D15 Drift cap parks.** A commit stamped beyond `MAX_DRIFT` ahead is parked until local time catches up, not joined with the clock held back (review 2026-10-16). §2.2.
- **D16 Expiry is value erasure, not a floor.** Expired writes keep their stamps and lose their values; resets, flags and positions stay. The review's floor at T diverges or overreaches. §4.7.
- **D17 Snapshots** carry per-node frontiers, no own writes, and no values of expiring commits. §8.
- **Open (owner):** acceptable state growth per commit (D12), and whether `max`/`min` need exact undo.
