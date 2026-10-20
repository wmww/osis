# CRDT specification
> Summary: Exact state, wire delta grammar, join, read, ops, undo, un-merge and tombstone rules for every merge encoding; encoding slots and embeddings; paging of large states; structural diff. The reference model `models/crdt/` implements it.

Two implementations of this document encode any state, delta or snapshot byte-identically (§3.3) and read it identically (§4, §5). It assumes only the commit header fields of §2.4 (spec/commits.md).

Notation: `[a, b]` is a CBOR array, `{k: v}` a CBOR map (int keys, sorted), `Opt(X) := [] | [X]`. `A < B` on stamps is the total order of §2.2. "Writer" is the node producing a delta, "reader" any node joining it.

## 1. Model

- An **aspect state** is a tree of **fragments**. Each fragment has a merge **encoding** (§3.1) that fixes its state shape, join and read. Nested fragments are self-describing, so join needs no schema. A position (aspect root, struct field, map entry value, list element content, enum payload) that has seen several encodings holds one fragment per encoding, joined pointwise (§7).
- A **write** is the smallest unit of authorship: one register value, one element creation, one reset, one flag or position change. Every write carries a **stamp** (§2.2): the commit's timestamp plus the write's **dot**. Writes are never modified, only superseded (later stamp) or pruned (older than a reset).
- A **delta** is a fragment of the same grammar as a state. Applying a delta is `join`. Join is commutative, associative and idempotent, so delivery order, duplication and partial receipt do not matter.
- A **reset** is a stamp stored in a fragment or collection element; every write under it with a smaller stamp is dropped. It is the only removal mechanism. Removal drops writes, never sequence element records: a record whose writes are all gone stays as a bare anchor (§5.7), so a newer insert anchored into removed content is still placed.
- **Read** is a deterministic function from state to an osis value (spec/data-model.md). Apps see only reads.

## 2. Stamps, dots, sources, clock

### 2.1 Sources and dots
A **source** is who minted a run of counters:
- `Node(tid)`: a node's signing identity (15-byte tid). Counters are per (aspect, node), contiguous, starting at 1, never reused. A node that cannot be sure of its last counter for an aspect (restored from backup, lost state) must not write node-form dots for that aspect again; it uses commit form.
- `Commit(id)`: the commit itself (32-byte commit ID). Counters are per commit, contiguous from 1 across all the commit's deltas (aspects get disjoint ranges). The header marks the form once per commit; a commit uses one form for all its writes.
- `Derived(dot)`: synthetic, never written by any writer. Produced only by lattice embeddings (§7) that need several identities out of a single register write with dot `dot`. Counters start at 1. Belongs to the author of `dot` for attribution, frontiers and un-merge.

A **dot** is `(source, counter)`, counter ≥ 1. A dot identifies one write forever, and doubles as the identity of the element it created.

### 2.2 Timestamps and stamps
- `ts` is one unsigned integer: `wall_ms * 2^16 + logical`, `wall_ms < 2^47`. HLC rules: a node's clock is `max(wall clock, last ts seen)`, where wall clock is the node's corrected clock (spec/sync.md §6), with `logical` incremented on equal `wall_ms`; on receiving a commit the clock advances to the commit's ts. A commit with `wall_ms(ts)` more than `MAX_DRIFT = 1 h` (format constant) ahead of the receiver's wall clock is **parked**: kept unjoined and counted as not received (frontiers, §8) until local wall time catches up, then joined normally. The node tiebreak lives in the dot, not in `ts`.
- A **stamp** is `(ts, dot)`. One commit has one `ts`; every write in it has that `ts` and its own counter, so stamps inside a commit are ordered by counter, matching the writer's sequential intent.
- Total order on stamps: by `ts`; then the dot. Dots of `Node` and `Commit` sources order by source kind (`Node` < `Commit`), then source bytes (tid, commit ID), then counter. A dot `(Derived(d), i)` orders as the sequence `(d.source, d.ctr, i)` against the `(source, ctr)` of any other dot, so an embedded write sorts right after the write it embeds and below every other greater write (§7). Two different writes never compare equal.
- "Later wins" everywhere means this order.

### 2.3 Counter consumption
A delta for one aspect gets the counter range `[lo, hi)` of its writer's source. Two kinds of writes:
- **Commit-level writes** share the stamp `(ts, source, lo)`, the **delta stamp**: register values, resets (fragment and element), deleted-flag writes, enum case writes, presence writes. One commit carries at most one such write per register, so they never need an order among themselves; against the commit's own reset they win by the `>=` rule (§4.2), which is the "reset, then content" shape of a replace.
- **Creations and position writes** each consume a fresh counter in op order, starting at `lo`: element creations (text/list element, set element, map entry, bag contribution) because the counter is the element's identity, and position writes because siblings written by one commit are ordered by counter (§6.1). The first creation of a commit shares counter `lo` with the delta stamp; the two are never compared (a creation is a different register from any commit-level write).
- `hi = max(lo + 1, last counter + 1)`: a delta with only commit-level writes still consumes one counter, so every commit sits inside its author's contiguous counter sequence and revoke frontiers (spec/permissions.md §5) cover it.
A reader checks that every own-source **write** (stamp) in a delta lies in `[lo, hi)`, that own-source dots used as element identities or anchors are either in `[lo, hi)` (created here) or below `lo`, and that creations and position writes use distinct counters. A membership commit may carry several deltas for one aspect sharing one range (spec/commits.md §2): their commit-level writes share `(ts, source, lo)` and their creations take distinct counters across the deltas.

### 2.4 What the commit header provides
- `ts` of the commit.
- Per aspect: `(tid, ak, counter range [lo, hi), delta hashes)` as in §2.3. Encoding IDs and the sources table are inside the delta (§3.2), not in the header. The header also carries a schema table `[(schema ID, revision)]` and per aspect an index into it, absent for untyped writes (spec/versioning.md §3); merge ignores them. A content commit carries one delta per `(tid, ak)`; a roster snapshot (spec/permissions.md §6) carries one `/members` delta per edge, and the aspect's delta is the join of all of them that the node holds.
- Dot form flag (node or commit).
- Snapshot marker (§8): a snapshot commit carries only foreign writes and consumes no counters (empty ranges). Import marker (spec/permissions.md §7): likewise, with re-sourced foreign stamps.
- `expires: T` (wall ms) per aspect, optional (§4.7).
- `undoes: commit id` for undo commits (§4.6).
Every other header field (author, actor, retention, purge request, delete tokens, signature) is outside merge.

## 3. Wire grammar

All deltas and snapshots are osis canonical CBOR (spec/data-model.md §5). A **delta** is `[nonce, Sources, Commits, Fragment]` (§3.2) with a 16-byte random nonce; it is self-contained, so projection, rewriting and import need no header context. The delta hash covers the whole array.

### 3.1 Encodings
| id | name | for schema types | read type |
|---|---|---|---|
| 0 | register | every scalar, tid, blob; default for int, float, string | the value |
| 1 | counter | `counter<int>`, `counter<float>` | sum of live contributions |
| 2 | max | `max<int>`, `max<float>` | max of live contributions |
| 3 | min | `min<int>`, `min<float>` | min of live contributions |
| 4 | struct | struct | struct |
| 5 | enum | enum (incl. option) | enum |
| 6 | set | set | set |
| 7 | map | map | map |
| 8 | list | list<T> | list |
| 9 | text | `text` (and `markdown`) | string |
| 10 | slots | (never a schema encoding) a position holding several encodings, §7 | the read of the chosen slot |

Unknown id (or an unknown nested id) parks the whole delta (spec/versioning.md §2). A parked delta is kept as bytes with its header tuple and re-examined after upgrade.

An `any` position (spec/data-model.md §3) has no encoding of its own: a write chooses the encoding of the value's kind (map → map, list → list, set → set, enum → enum, everything else → register), recursively; kinds written at different times meet as slots (§7).

### 3.2 Grammar
```
Delta    := [nonce, Sources, Commits, Fragment]
Snapshot := [nonce, Sources, Commits, Fragment, Frontiers]   ; snapshot deltas, §8
Sources  := [Source*]                    ; foreign sources, §3.3 rule 1
Source   := bytes(15) | bytes(32) | [Src, ctr]   ; Node tid | Commit ID | Derived of a dot whose source is Node or Commit
Commits  := [[Src, [[dwall, logical, base]*]]*]   ; §3.3 rule 1
Ts       := uint                         ; §2.2
Src      := uint                         ; index into Sources, 0 = own (node form: the author node; commit form: this commit; not stored)
Ci       := uint                         ; commit index: 0 = this commit, i = Commits entry i (flattened)
Dot      := ctr | [Src, ctr]             ; ctr alone means own source
Stamp    := Ci | [Ci, ctr]               ; Ci alone means that commit's base counter (own: lo)
R        := Opt(Stamp)                   ; reset
W        := Opt(Stamp)                   ; explicit presence stamp, see §3.3
Anchor   := 0 | Dot                      ; 0 = HEAD (counters start at 1, so no clash)
Value    := any osis canonical value

Fragment := Register | Bag | Struct | Enum | Set | Map | Seq | Slots
Register := [0, R] | [0, R, Stamp] | [0, R, Stamp, Value]   ; [0, R, Stamp]: value-less write (§4.7)
Slots    := [10, Opt(Register), [Fragment*]]  ; §7: register slot, then non-register slots by ascending encoding id, at least two members in all
Bag      := [1|2|3, R, W, [Elem*]]           ; Elem as in Set; the value register holds int|float (anything else, only from §7, reads as nothing)
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
**Commits** is the delta's table of every commit other than this one whose stamps appear in the fragment (a commit is a `(ts, source)` pair; `Src` 0 entries name the writer's own earlier commits). Entries are grouped by source in `Src` index order; within a group ascending by `ts`; `dwall` is the difference of `wall_ms` to the previous entry of the group (absolute for the first), `logical` the low 16 bits of `ts`, `base` the smallest counter of that commit's stamps in this delta. Commit index 0 is this commit `(header ts, own, lo)`. A stamp encodes as its commit index alone when its counter equals the commit's base, which is every commit-level write (§2.3) and the first creation. A writer's delta carries only its own stamps (anchors are dots, not stamps), so its table is empty; the table is populated in snapshots (§8).

**Run** semantics: a run describes elements `e_i` with dot `(first.source, first.ctr + i)`, `0 <= i < n`. With a `Creation`, the run **creates** them: segment `[Ci, k]` gives the next `k` elements the creation stamp `(ts(Ci), first.source, first.ctr + i)`; `e_0` anchors at `Anchor`, `e_i` (i > 0) at `e_{i-1}`. Without a `Creation` the run carries writes on elements that exist elsewhere, or, with nothing else, bare anchors (records whose writes were all pruned, §5.7; a snapshot emits them as `[Dot, n, [], [], [], []]`). `Content` lists, in order, the content of the run's elements that **carry content**: text, one char (Unicode scalar value) per element not deleted after the run's `FlagW` are applied; list, one fragment per element whose fragment is non-empty (§4.2 Emptiness) after the run's `FlagW` (element resets, §5.7) are applied; a list run is uniform in this (rule 3), so a list `Content` is empty or has exactly `n` fragments. `[]` means no content carried for any element (a pure flag or position delta, or, with a `Creation`, value-less creations, §4.7). `PosW` are position writes other than the creation write; `FlagW` are deleted-flag writes for text and element resets (`true` only) for lists (§5.7).

Set elements have no key; their value is a `Register` fragment. A map entry's key is immutable and is repeated in every record of that entry (it is needed to resurrect an entry whose tombstone has lost it, §5.6), except tombstones and entries whose creation is value-less (§4.7), which use the keyless form.

### 3.3 Canonical rules (byte-for-byte determinism)
1. `Sources` lists foreign sources in order of first appearance in the `Fragment`'s canonical encoding (stamps and dots alike, as they are encoded; a `Derived` source is preceded by its underlying source), then the frontier-only sources of a snapshot (§8) in ascending source-byte order. `Commits` holds exactly the commits other than this one with stamps in the fragment, grouped and ordered as in §3.2, each with `base` = its smallest counter in this delta. A `Dot` or `Stamp` uses the bare form whenever it can.
2. Arrays of elements, entries, runs are sorted by dot (source as in §2.2, then counter), except that a commit-form delta's own source sorts below every other commit ID (its writer encodes before the commit ID exists). `PosW` sorted by `i`, then stamp descending; `FlagW` by `(i_from, Stamp)`; segments in element order with adjacent equal `Ci` merged. Maps sort by canonical key bytes as all osis maps do.
3. Runs are maximal, up to `2^16` elements per run. A creation run extends over consecutive dots of one source as long as each element's creation write exists in the state, `e_i` was created anchored at `e_{i-1}`, and "carries something" (text: deleted flag `true` or has a char; list: has a reset or a non-empty fragment) and, for lists, "has a non-empty fragment" are the same for all. A non-creation run extends over consecutive dots that all have no creation write, no position writes, the same deleted write or element reset, and the same "carries something" and, for lists, "has a non-empty fragment".
4. `W` is encoded whenever the state holds a surviving explicit presence write (§4.3). A `Slots` position lists its members in the order of §3.2 (§7); a position with one member is that member, never a `Slots`.
5. A fragment never carries writes already implied by another write in the same delta (e.g. a creation run does not list its creation position writes in `PosW`), and a snapshot never carries content for deleted elements.
6. Own-source counters lie in the header range; creations and position writes have distinct counters (§2.3).
7. A reader rejects a delta (bad input, never a panic) if: non-canonical CBOR; a `Src`, `Ci` or counter is out of range or 0 where 1 is the minimum; a non-canonical table order or bare/array form; a segment's commit has another source than the run; n = 0 or n > `2^16`; a `FlagW` or `PosW` index out of range; a `FlagW` `false` in a list run; a non-empty `Content` whose length differs from the number of content-carrying elements of the run; a `Register` with a reset below a nested level (only aspect roots and the members of a `Slots` carry one); a keyed `Entry` without a fragment (tombstones are keyless); a `Slots` in a writer's delta, or one with fewer than two members, a non-register first member, unsorted or repeated slot encodings; a creation run of a `Derived` source in a writer's delta (only snapshots carry embedded characters, §7); a bare-anchor run (no `Creation`, `Content`, `PosW` or `FlagW`) outside a snapshot; in a writer's or import delta, runs with empty `Content` of more than `MAX_DELTA_BARE` = 2^18 elements in all, pages included (a delete or move of more elements is split across commits; `replace` and `remove_aspect` clear any length with one reset); a `FlagW` stamp of a writer's delta other than the delta stamp (§2.3); foreign stamps in a delta that is neither a snapshot nor an import (spec/permissions.md §7).

## 4. Join, prune, presence (all encodings)

### 4.1 Join
`join(A, B)` where both are the same encoding: take the union of all writes, keeping for each register the write with the greatest stamp, for each reset the greatest stamp, for each collection the union of elements by dot (joining records of one dot recursively), then **prune** (§4.2). Different encodings: §7. Join of a state with a delta is the same operation; a state is just a fragment with every stamp written in full. Join is commutative, associative and idempotent.

### 4.2 Prune
Every fragment has an **effective reset** `E = max(E_parent, own R)`, with `E_root = own R` and `-inf` where none. A write with stamp `s` survives iff `s >= E`. Equality means the write and the reset come from the same commit (a replace: reset and content share the delta stamp, §2.3; embeddings §7 do the same), and then the content wins. Rules per structure:
- Registers: the write is dropped if `s < E`.
- Composites: the presence stamp (§4.3) is dropped if `< E`; children are pruned with `E` as their parent reset. A nested fragment's own `R` below `E_parent` is dropped like any other write.
- Collection elements: the element's own `R` survives iff `>= E_parent`; its content is pruned with `E_elem = max(E_parent, R_elem)`. A set, bag or map element record whose content is entirely pruned and whose own `R` is dropped is removed from the state. One whose content is pruned but whose `R` survives is a **tombstone** (dot plus reset stamp, nothing else). **Seq element records are never removed by prune**: a record whose writes are all pruned is a **bare anchor** (dot only), placed at END (§6.2) and never emitted, so writes anchored to it stay placeable. The one exception is a `Derived`-source record (§7), which exists only while it carries a write (§4.7, §6.1).
- **Emptiness.** A fragment is empty iff it holds no surviving write and no record at any depth. Record existence is grow-only, so a struct field, map entry or list element whose only remaining content is a sequence of bare anchors is kept.
- `Slots` positions (§7) have one effective reset `E = max(E_parent, greatest member reset)`; every member is pruned under it, so a member's own reset below it goes.
- A delta, after pruning against the state it joins, may contribute nothing. That is normal.

### 4.3 Presence
- A register is present iff it holds a surviving valued write (a value-less winner, §4.7, is absent).
- A composite (bag, struct, enum, set, map, seq) has a **presence stamp** `written` = the greatest stamp among all writes inside it (its children's writes, element creations, element resets, nested resets, case writes, position and flag writes), excluding its own reset and value-less writes (§4.7), plus any explicit `W` write. It is present iff `written` survives (`written >= E`). `written` is a function of the surviving writes; only explicit `W` writes are stored, so expiry can lower it. For sequences, a creation counts iff the element has content, is deleted (text) or reset (list) (a non-deleted element without content is a value-less creation), and a deleted text element's content does not count (it is never on the wire). This makes an explicitly written empty collection present, and a collection emptied by removals present (the removal is a write inside it), while `remove_aspect` (reset with nothing after) makes it absent.
- An aspect is present on a thing iff its root fragment is present. `/aspects` reads the present ones.
- A writer emits an explicit `W` (a commit-level write at the delta stamp, §2.3) only when creating or replacing a composite with no content writes in the same delta (an empty set, an empty struct). `W` is a write like any other for frontiers and un-merge, and is always carried on the wire while it survives (§3.3 rule 4).

### 4.4 Read
Defined per encoding in §5. Reading a fragment that is not present yields "absent"; inside a struct that is a missing field (reader default or typed-read error, spec/versioning.md §5); inside a map entry or list element it means the element is not live.

### 4.5 Writes an op produces; a commit is a net effect
Local ops are resolved against local state at write time (index paths, keys, values become dots) and produce one delta per touched aspect; sections 5.x list each op's writes. Resolving against local state is what makes removals name only observed dots: an add the remover never saw survives.

A delta is a state fragment, so a commit carries the **net effect** of the ops batched into it, not their history: a register written twice carries the last value; all deletions of one commit are one flag write (the delta stamp); an element created and removed within the same commit is omitted once no other write of the commit anchors at it (chained creations, position writes of moved elements), repeatedly, so a removed chain goes whole; one still named stays, created and removed, since re-anchoring what names it would reorder it among the anchor's other children (stamps do not change). Nothing outside the commit can have observed the omitted writes.

### 4.6 Undo (cancel per dot) and un-merge (by author)
Undo is a new commit with `undoes` set; its deltas are ordinary writes chosen per original write:
- element creation (text/list insert, set add, map put, contribution): text → deleted-flag write `true` on the dot (keeps the anchor; §5.7); list/set/map/bag → element reset on that dot.
- register write, position write: write the previous value (from the undo buffer, the state before the undone commit) if the undone write is still the current winner locally, or if all of: the current winner was written by an undo commit in effect; it equals the undone write in value (register value or anchor; a value-less write, §4.7, equals nothing); and every commit that is not an undo commit, holds writes of the aspect and is ordered after the undone commit (by `(ts, ID)`) is not in effect. Otherwise no write. A commit is **in effect** while no undo commit in effect undoes it. So undo steps back through repeated edits of one position, never over a live later change.
- flag write, element reset (text delete, list delete, set remove, key remove): the inverse write (flag `false` for text, or a re-add with a fresh dot) carrying content from the undo buffer, at the undo commit's stamp; a map key's removed entries are re-added as one entry carrying their joined value.
- fragment reset (remove_aspect, replace, enum case write): re-insert the pre-reset value from the undo buffer with fresh dots (`replace`); bags: §5.2.
Originals whose body was dropped are not undoable. Redo = undo of the undo commit.

**Un-merge** (revocation, spec/permissions.md §5): the state after un-merging an author is the join of every body and value-less residue (§4.7) the node holds for the aspect (its own current state counts as a snapshot it holds, so live writes of bodies dropped under keep-at-most survive), each with the writes whose dot's source belongs to that author removed (`Derived` dots count for the author of the underlying dot; writes a valid snapshot carries stay, spec/permissions.md §6). It is a function of the held set, never of the order in which the commits and the revocation arrived. Seq elements created by the author keep their record as a content-less, hidden anchor (`Derived` records with no remaining write go, §4.7). Removing the author's writes from the state in place is permitted only where it gives that join; a register or position whose winner or top-2 (§5.7) the author held needs the retained bodies.

### 4.7 Expiry and value-less writes
A delta with `expires: T` (header, per aspect; `T > wall_ms(ts)`, else the commit is rejected) owns the writes of its source with a counter in its range (commit form: every write of its source in that aspect). Its **value-carrying** writes are register values, enum case writes, set and bag element values, map entry creations (the key is the creation's value) and sequence element creations (the text char or list element). Its other writes (resets, `W`, deleted flags, position writes) carry no app data. Writes are attributed by dot: a write, element or entry belongs to the delta whose range holds its dot (a `Derived` dot to the delta of its underlying dot).

- **Value-less writes.** A value-carrying write may be held without its value: stamp kept, value gone. Join: the copy with the value wins over the copy without (copies of one write always carry the same value), so the lattice is unchanged. A value-less write takes part in "later wins" like any other but reads as absent: a register whose winner is value-less is absent; an enum whose case winner is value-less is absent and its payloads stay hidden until a reset sweeps them (§5.4); a set or bag element (whose value register only its creation writes), map entry or sequence element whose creation is value-less is not live. A map entry keeps its nested writes, hidden, until a reset sweeps them (the entry's key is not stored, and a key repeated in another record is ignored). A text element keeps its creation write (anchor) and drops its char; a list element keeps its creation write and loses the content writes of the expiring delta, while nested writes of other deltas survive and show (spec/requirements.md, Data model); a text element so stripped is the same hidden anchor un-merge leaves (§4.6). An embedded character (`Derived` dot, §7) has no creation write apart from the value, so it goes entirely: creation and content; position and flag writes of others stay, and a record with none of those is dropped (a node that only ever saw the value-less register has no such record either). Writes anchored at a `Derived` dot that is not in the state are still placed: §6.1 treats such an anchor as a bare anchor at END, since the dot is known from the delta's `Sources`. Value-less writes do not count toward `written` (§4.3).
- **Expiry rule.** Once a node's wall clock reaches T it holds every value-carrying write of the delta value-less, and strips the value from any copy that arrives later (an undelete repeating the content, a stale peer, another projection); it knows T from the commit header, which outlives the body. Its non-value writes stay. Its value-carrying writes are dead at T (§4.8) and its body is dropped (spec/commits.md §6). A node holding a valid purge request treats the value-carrying writes it names the same way from the moment it applies it (spec/commits.md §5).
- A delta writing inside an element created by an expiring delta (a reaction to a disappearing message) repeats its key or anchors to it; the writer SHOULD give it an expiry no later than T.
- Snapshots carry the delta's value-carrying writes value-less, before and after T, and never cover it, so its content lives only in its own blob, which blind nodes drop at T (§8). Before T a node holding the snapshot but not yet the delta reads those writes as absent, like any partial receipt.

### 4.8 Death of a write
A write is **dead** at a node once the join has superseded it: pruned by a reset (§4.2), a register's reset implied by its later write (§5.1) included; beaten as a register, case, flag or position winner by a greater stamp; its element deleted or tombstoned; or its value gone by expiry (§4.7). It dies at the `ts` of the superseding commit, or at T. Un-merge (§4.6) is the only way a dead write revives. Retention tracks deaths per body (spec/commits.md §5).

## 5. Encodings

Each encoding below gives: state, delta shape (= grammar of §3.2, restated where helpful), join specifics beyond §4.1, read, ops, tombstones. Notation for op deltas: `D` is the delta stamp (bare `0` on the wire), `k, k+1, …` fresh counters (§2.3).

### 5.1 Register (0)
- State: `R`, optional write `(stamp, value)`. Nested registers (struct fields, enum payload leaves, set element values) never carry their own `R` (always `[]`); only an aspect whose root is a register uses it, and the register slot of a `Slots` position may (§7). An `R` below the write's stamp is dropped: the write resets everything older at the position (§7), so it implies `R`.
- Join: greater stamp wins. Prune per §4.2.
- Read: the value.
- Ops: `set v` → `[0, [], D, v]` = `[0, [], 0, v]`. `remove_aspect` (root) → `[0, [D]]`. `replace v` (root) → `[0, [D], D, v]` (reset and content share the delta stamp; content wins by `>=`).
- Undo of a write: previous value if still winner (§4.6).
- Tombstones: none; the reset stamp is the whole removed state.

### 5.2 Bags: counter (1), max (2), min (3)
- State: `R`, `written`, elements `{dot: (R_elem, value register)}` exactly as a set (§5.5); the register holds the contribution amount (int or float per the aspect type). The register's first write has the element's creation stamp.
- Join: as set; prune.
- Read (bit-identical on every node): counter = sum of live contributions; ints are summed exactly and the sum clamped to i64 (never a panic), floats are summed as f64 in dot order (§2.2), and a bag holding both (only via §7) reads as float sum plus int sum. max/min = the extreme under this order: int against int by value, anything involving a float by IEEE 754 totalOrder on f64 (-0.0 < 0.0, the canonical NaN greatest); among equal extremes the one with the lowest dot. Absent when nothing is live and `written` does not survive.
- Ops: `inc(a)` → one element `[k, [], [[0, [], D, a]]]`. Contributions that are not numbers (only from a register embedding, §7) are ignored by read. `set v` (a replace) → fragment reset `D` then one element `k`. For max/min a bare contribution is "observe v".
- Undo of a contribution = element reset on its dot (cancel per dot, idempotent when two devices undo the same inc). Undo of a `set` or `remove_aspect` = an element reset on the undone commit's own contribution (if any), plus the pre-reset live contributions from the undo buffer re-added with fresh dots; no fragment reset, so contributions others made after the undone commit survive.
- Tombstones: as set elements (§5.5). No GC: dropping non-extreme max/min elements or folding contributions is not permitted.

### 5.3 Struct (4)
- State: `R`, `written`, `{field_id: fragment}`. Field IDs are the schema's wire IDs; unknown IDs are kept and joined like any other.
- Join: per field; prune.
- Read: struct with every present field. Missing fields are the reader's problem (defaults, spec/versioning.md §5). An unknown field ID is read as data (`Value` API) and ignored by typed reads.
- Ops: `set_field(id, v)` → `[4, [], [], {id: diff-delta of v against the field's local state}]` (structural diff §9, so a field of composite type gets nested writes). `replace` of the struct → `[4, [D], [], {id: fragment of each field}]`; a struct with no fields → `[4, [D], [D], {}]`.
- Tombstones: none beyond `R`.

### 5.4 Enum (5)
- State: `R`, `written`, case register `(stamp, case_id)`, payloads `{case_id: fragment}`. Payload writes are filed under the case they were made for; the payload of a case that is not current stays in the state, hidden, until a reset sweeps it.
- Join: case register by stamp; payloads per case; prune (payloads of a non-current case are pruned by `E` like any other fragment, so a case change, which is a reset, drops every older payload write of every case).
- Read: `[case_id]` or `[case_id, read(payloads[case_id])]`. A payload fragment that is absent for a case that has a payload type is a typed-read error (missing payload), never a panic. If the case register is absent the enum is absent, whatever payloads exist.
- Ops: `set_case(id, payload)` where id differs from the current case → `[5, [D], [], [[D, id]], {id: payload fragment}]` (reset, case write, payload). Same case with a changed payload → `[5, [], [], [], {id: diff-delta}]` (no case write). `option<T>`: `none` is a case without payload: `[5, [D], [], [[D, 0]], {}]`.

### 5.5 Set (6)
- State: `R`, `written`, elements `{dot: (R_elem, value register)}`. The value register's first write has the element's creation stamp.
- Join: union by dot; per element `R` max and register max; prune (§4.2). A tombstone is `(dot, R_elem)`.
- Read: the set of distinct values of live elements (live = register present under `E_elem`). Equal values from several elements read once. Large values compare by keyed content hash (spec/data-model.md §6); of equal links the read shows the one of the lowest live element in dot order (§2.2).
- Ops (resolved locally): `add v`: if an element with value v is live locally, no write; else `[6, [], [], [[k, [], [[0, [], D, v]]]]]`. `remove v`: for every live local element with value v a record `[dot, [D], []]`; all removed elements share the one reset stamp `D`. `replace {v1..}` → fragment reset `D`, then adds with fresh counters.
- Tombstone lifetime: until the set fragment is reset (`R_elem` is pruned like any write below `E_parent`). Until then it drops a late-arriving older add. No other GC: state grows with removals ever made (spec/requirements.md, Scale).

### 5.6 Map (7)
- State: `R`, `written`, entries `{dot: (R_entry, key, fragment)}`, plus a local index `key -> live dots` (not part of the lattice). The key is immutable and repeated in every record of the entry on the wire that carries a fragment. An entry is live iff its key is known and its fragment is present.
- Join: union by dot; per entry `R` max, fragment join; prune. Tombstone = `(dot, R_entry)`; the key is dropped with the content (content-free tombstone).
- Read: for each key with at least one live entry, `read(join of the live entries' fragments)`. Two live entries with one key (concurrent puts) read as one merged value; with equal links as keys (spec/data-model.md §6) the read shows the key of the lowest live entry in dot order (§2.2).
- Ops: `put(key, v)`: if a live entry with that key exists, write `v` by structural diff (against the key's read, the join of its live entries) into the **lowest live dot** (lowest in §2.2 dot order) and leave the others alone; else create `[k, [], key, [fragment of v]]`. `remove(key)`: the reset stamp `D` on every live dot with that key, keyless records `[dot, [D], []]`. `set_field` and other path ops into an entry go to the lowest live dot. `replace` of the map: fragment reset then puts. `put_new(key, v)`: create `[k, [], key, [fragment of v]]` whatever is live (a concurrent put's shape: the delta carries `v` whole and resets nothing); at a register position other than a map key, `put_new` writes the register with no reset (even when equal); at any other position it is refused.
- Resurrection: a nested write newer than the entry's reset makes the entry live again holding only the surviving writes; the record carries the key so the reader can index it. An older nested write is dropped by the tombstone. This is why map tombstones live **until the map fragment is reset** (then every tombstone older than the reset is itself pruned). No other GC.

### 5.7 Sequences: list (8) and text (9)
Text is `list<char>` with run compression and immutable element content; list elements carry a recursive fragment. The two differ in how an element is removed: text by a **deleted flag** (content is immutable, so an undelete restores it exactly), list by an **element reset** (content is a mergeable fragment, so a concurrent newer nested write must survive and show, as in maps; spec/requirements.md, Data model).

**State** per element (identity = creation dot):
- `created`: the creation write `(stamp, anchor)`, kept as long as it survives pruning even when two later moves have pushed it out of `pos`. Text content has no stamp of its own: it is present iff `created` is.
- `content`: text: the char, immutable (an implementation may drop it locally once the element is deleted; a later undelete delta or a specific-blob fetch restores it). List: a fragment, joined like any other and pruned under `E_elem = max(E_parent, R_elem)`.
- `pos`: the two greatest position writes `(stamp, anchor)` seen (top-2 under §2.2), the creation write included: `cur` and `prev`. Top-2 of a union is the top-2 of the union of top-2s, so this is a lattice.
- text: `deleted`, LWW register of bool; absent means false. Its writes may cover ranges (`FlagW`). list: `R_elem`, the element reset (greatest stamp), written as `FlagW true` over a range; a list element is **deleted** iff its content fragment is absent.
- Element existence: a record is never dropped (§4.2). A record with no surviving write is a **bare anchor**: not read, emitted only in snapshots, placed at END (§6.2), and a valid anchor for later writes. Text content lives and dies with the creation write: an undelete newer than a reset that pruned the creation revives the flag, not the content (the content has no stamp of its own; a node that dropped it locally could not have carried it either). `Derived` records are the exception and go with their last write (§4.7).

**Join**: union by dot; `created` and text content: first seen (all copies are equal); list fragment join; pos: top-2 of union; deleted: max stamp; `R_elem`: max; prune.

**Read**: the linearization (§6) of elements that are not deleted and have content, mapped to their content (text: concatenated string; list: list of `read(fragment)`).

**Ops** (all resolved against local state; index paths never go on the wire):
- `insert(after: index|HEAD, items)`: one creation run `[k, n, [anchor, [[0, n]]], content, [], []]`, anchor = dot of the element visually at `index` (HEAD for 0). Elements get dots `k..k+n`.
- `delete(range)`: for each maximal run of consecutive dots in the range, a record `[first, m, [], [], [], [[0, m-1, D, true]]]`; the one delta stamp for the whole commit. Text: content of the deleted elements may be dropped locally. List: the element reset prunes the elements' content below `D`.
- `undelete(dots)` (text only): same with `false`, content carried in `Content` (from the undo buffer or clipboard) so readers that dropped it recover it. A list element is restored by re-inserting its value with a fresh dot.
- The **range** of a delete or move is the slice of the full placement order (deleted elements included, §6.1) from the first to the last visible element of the selection, so hidden anchors inside a selection travel with it; trailing deleted elements stay behind.
- `move(range, after: index|HEAD)`: let `roots` be the elements of the range whose chosen parent (§6.2) is outside the range, in visual order; `pred` the visible element before the range (or HEAD); `outside` the elements outside the range whose chosen parent is inside it, in visual order (typically the subtree roots of the range's successors). Writes, each consuming a counter: first the `outside` elements **in reverse visual order**, each a position write to `pred` (reverse, because siblings read greatest-first: the one written last lands nearest `pred`); then root 1 to the destination anchor; then root j>1 to the last element, in placement order, of root j-1's moved subtree (its subtree minus the `outside` subtrees). Interior elements of the range are never rewritten (rewriting would change their sibling keys and reorder concurrent neighbours).
- `cut` = delete range (client remembers the dot ranges beside the clipboard text); `paste` in text = `move` of the remembered roots to the destination + `undelete` of the range when the clipboard still matches the remembered ranges, else a plain insert. The protocol has no clipboard concept.
- List element edits: `set_field`/nested ops on element i → record `[dot, 1, [], [nested fragment], [], []]`. A nested write newer than the element's reset makes the element live again holding only the surviving writes (spec/requirements.md, Data model).
- `replace(items)`: fragment reset `D`, then a creation run. Old elements lose every write below `D` and stay as bare anchors, so a concurrent insert newer than `D` anchored into the old content appears after the new content (§6.4, "Reset against a newer insert"); an older one is dropped like any older write. `remove_aspect` is the same without the creation run: the aspect reads absent, the anchors remain.

**Undo**: insert → text delete flag, list element reset; text delete → undelete with content; list delete → re-insert with a fresh dot; move → position write back to the pre-move anchor if the undone write is still `cur`, or as §4.6 steps back. Delete and move resolve independently: a moved-and-deleted element is a hidden anchor at its new place.

**Tombstones**: a deleted element keeps its record (dot, pos top-2, deleted flag or element reset) forever, and after a reset a bare anchor (dot only, about one byte per run in a snapshot); a deleted element is 3–4 bytes in a run-compressed snapshot. State therefore grows with the number of edit runs ever made and never shrinks, resets included (spec/requirements.md, Scale). There is no tombstone compaction.

## 6. Linearization

A deterministic function of state. Correctness never depends on it (convergence is by join); it only decides what users see.

### 6.1 Tree and order
- Every element has an **anchor**: `HEAD` or another element's dot. Children of X are the elements whose chosen position write (§6.2) anchors at X, ordered by that write's stamp, **greatest first** (a newer insert at the same anchor goes nearer the anchor; a moved element lands directly after its target, ahead of the target's older children).
- The order is the depth-first traversal from HEAD: X, then each child subtree in sibling order. Deleted elements and elements without content are traversed (their children are placed) but not emitted.
- An element whose chosen anchor is not in the state (its creation has not arrived) is **hidden** with its whole subtree until the anchor arrives. Since records are never pruned (§4.2), this is always a transient of delivery, never the result of a reset. An anchor naming a `Derived` dot (§7) that is not in the state is treated as a bare anchor at END (the record went with its value, §4.7; the dot itself is known from `Sources`), so the element is placed, not hidden.

### 6.2 Choosing a position: cycles
Position writes are rewritten only by moves, so a cycle in the anchor graph contains at least one move edge. Algorithm, run on the whole state (incremental implementations must produce the same result):
1. Every element starts on candidate 0: `cur`. Candidates after that: `prev` (if any), then `END`.
2. While the anchor graph (over elements with a known anchor) has a cycle: among the cycle's elements, demote the one whose **current edge has the smallest stamp** to its next candidate. `END` breaks every cycle, so this terminates.
3. An element on `END` anchors at HEAD with a virtual stamp below every real stamp, ordered among `END` elements by dot ascending; it therefore appears after every real top-level subtree, at the end of the sequence, with its subtree. An element whose `prev` anchor is unknown skips to `END`. Bare anchors (§4.2) have no position write and are on `END` from the start.
Cycles are vertex-disjoint (every element has one current edge) and each demotion is forced, so the result does not depend on which cycle is found first.

## 7. Encoding slots and lattice embeddings

A position may see fragments of different encodings: an aspect upgraded from `string` to `text` (spec/versioning.md §4), or two schemas claiming one AK (spec/requirements.md, Versioning). The state at such a position is a **`Slots`** fragment: an optional **register slot** plus one slot per non-register encoding seen, joined **pointwise** (same encoding: §4.1; absent on one side: taken). Writers never produce `Slots`; a delta always has one encoding, and the join forms the position.

**Embedding.** The register slot is embedded into every non-register slot: after a join, each slot `X` is `X ⊔ embed(R)`. `embed` is total from a register into every non-register encoding and depends only on the register fragment `{R: r, write (s, v)}`:
| target | embed |
|---|---|
| counter, max, min | reset `max(r, s)`, one contribution element with dot `s.dot` whose register holds the write `(s, v)` |
| text | reset `max(r, s)`; if v is a string, elements with dots `(Derived(s.dot), i+1)` for the i-th char, all stamps `(s.ts, Derived(s.dot), i+1)`, chained from HEAD, content = the chars; otherwise nothing |
| struct, enum, set, map, list | reset `max(r, s)` only |
A register with no write embeds as reset `r` only. A contribution that is not an int or float reads as nothing (§5.2). The edges are total, so a value-less write (§4.7) embeds exactly like its valued copy. Embedding commutes with join, so applying it eagerly after every join equals applying it at read.

**One reset per position.** The effective reset of a `Slots` position is the greatest reset among its members (and the parent's); prune uses it for every member (§4.2). So a `replace` or `remove_aspect` in any encoding removes everything older at the position, whatever encoding wrote it, and a register write (an old app's save) is a reset of everything older in every slot plus its content where an edge exists.

**Read.** A `Slots` position reads as its **chosen** member: the one with the greatest stamp anywhere inside it (resets included), ties by greater encoding id; the position is present iff that member is. Since every non-register slot holds the register's embedding, a slot's greatest stamp is at least the register's, so the register is chosen only when it is alone, and then the position is just that register. Two unrelated encodings at one position therefore read as "later writer wins", with the other encoding's history kept and readable again should it be written last later. Ops (§4.5, §9) see the position's read and write into the slot of their schema's encoding; a slot that does not exist yet is created by the write.

**Canonical form.** A position with a single member is that member, never a `Slots`. A member is dropped when it is empty or adds nothing to the register slot's embedding (`m ⊔ embed(R) = embed(R)`), so the members are a function of the surviving writes and do not depend on arrival order. Wire form in §3.2; §3.3 rule 7 for what a reader rejects.

`Derived` dots never go on the wire from a writer, but a new-app insert anchored to an embedded char references `(Derived(s.dot), i)` through the delta's `Sources` (§3.2), and a snapshot of such a text carries them. A `Derived` record exists only while it carries a write (§4.7); an anchor naming an absent one still places (§6.1).

There are no other edges.

## 8. Paging (large deltas, states and snapshots)

Principle: deltas, state and snapshots are the same grammar, so any fragment's collection arrays may be replaced by links to **pages**.

- Grammar extension: in `Bag`, `Set`, `Map`, `Seq`, the element array may be `[Link*]` (each a LINK-tagged value, spec/data-model.md §5) instead of `[Elem*]`; a page blob is a canonical CBOR array of elements (`[Elem*]`, `[Entry*]`, `[Run*]`), or again `[Link*]` (at most 2 levels: a root of links to pages of links to pages). A fragment is paged iff its element array as plain CBOR would exceed `PAGE_TARGET = 64 KiB`; a paged array is split into pages at content-defined boundaries over the canonical bytes of consecutive elements (gear hash, min 16 KiB, max 256 KiB, shared with spec/data-model.md §6; exact rule and link pages: spec/wire.md §6), so equal element runs give equal pages whatever the history; a page holds whole elements, so one element above the maximum is a page by itself. Canonical: paging is mandatory above the threshold and forbidden below, so two nodes snapshotting identical states produce identical bytes. Pages are blobs under random keys like chunks (spec/data-model.md §6).
- Join of a fragment with links: the reader fetches every page before its commit is applied (spec/commits.md §4) and joins their elements; a page's elements are all keyed by dot, so pages are joined independently, streaming.
- **Snapshot deltas** are `[nonce, Sources, Commits, Fragment, Frontiers]` with `Frontiers := [[Src, ctr]*]`, sorted by `Src`, one entry per `Node` source with `ctr` ≥ 1 the largest counter such that the writer has applied all of that node's writes in this aspect up to it (parked commits are not applied, §2.2). The fragment reflects every write in those ranges; a receiver adds `[1, ctr]` to its received-dot ranges for (aspect, node) for revoke frontiers (spec/permissions.md §5.1), and learns the node's tid from `Sources` (frontier-only sources come last, §3.3 rule 1). `Commit` sources have no frontier. A snapshot commit carries no writes of its own and consumes no counters (§2.4).
- Snapshots never carry the values of writes from deltas with an expiry, expired or not, or of writes named by a purge request the writer holds (§4.7): those writes go value-less and their deltas are never covered. Live content of any other delta is carried as usual, whatever its retention.
- Any delta may page, so a commit has no size limit (spec/commits.md §1): a bulk import or a reset of a huge map is one atomic commit.

## 9. Structural diff

Input: local state fragment `S` (may be absent), new value `v`, and the writer's **view**: a projection of read values onto what the writer's schema can type (identity for untyped writes). The edit script is not normative: any script with `read(join(S, diff(S, v))) == v` is valid, and two implementations may emit different deltas for one call. What is normative is the identity rule: an element the script keeps or edits keeps its dot (so concurrent writes into it survive), and only elements the script deletes lose theirs. Every equality below compares `view(read(...))` with `v`'s side; an element or entry whose `view` fails (unknown enum case, type mismatch) is **opaque**: never matched, never removed, never re-inserted, and left where it is (spec/versioning.md §5). Output: writes, as a delta. Rules per encoding, recursive:
- register: write iff `read(S) != v` (bit-exact for floats) or S absent.
- bag: counter: `inc(v - read(S))` if different; max/min: reset + contribution if `v != read(S)` (a max cannot go down otherwise).
- struct: per field of `v`: recurse into `S.fields[id]`. Fields present in S but not in `v` are left alone (open structs: the writer only knows its fields; a typed `v` always has all the writer's fields). A field absent in S whose value in `v` equals the field's declared default produces no write (defaults are never materialized).
- enum: same case → recurse into the payload; different case → `set_case`.
- set: adds for values in `v` whose `view` matches no live element; removes for live, non-opaque elements whose `view` is not in `v` (one reset stamp). Large values compare by keyed content hash.
- map: keys (under `view`) only in `v` → put; non-opaque keys only in S → remove; both → recurse with the key's read (the join of its live entries) as S, writing into the lowest live entry.
- list: opaque elements are removed from consideration first and keep their place; LCS (Myers) over the rest with equality = `view(read(elem)) == item` (deep); unmatched old elements and new items are then **paired in order** while both remain and recursed into (a changed entry is an edit, not delete+insert); leftover old → delete (element reset), leftover new → insert after the preceding matched/paired element.
- text: Myers diff over chars → deletes and inserts (no move detection). Equal strings → no writes.
- absent S: everything is a creation; composites with no content get an explicit `W`.
A replace ignores S: fragment reset then the writes of a diff against absent.
S is compared as it reads now (§4.7): a value-less write reads as absent, so its position is written again; a value still carried is matched and keeps its expiry, and goes at its T even though the new delta lives longer. A writer needing all of `v` to live as long as its own delta writes a replace.
