# CRDT specification
> Summary: State, delta grammar, join, read, ops, undo and un-merge of every merge encoding, with encoding slots, paging and structural diff.

Two implementations of this document encode any state, delta or snapshot byte-identically (§3.3; up to the delta nonce and the blob IDs and keys of page links) and read it identically (§4, §5). It assumes only the commit header fields of §2.4 (spec/commits.md).

Notation: `{k: v}` maps in this file have int keys, sorted. `A < B` on stamps is the total order of §2.2. "Writer" is the node producing a delta, "reader" any node joining it.

## 1. Model

- An **aspect state** is a tree of **fragments**. Each fragment has a merge **encoding** (§3.1) that fixes its state shape, join and read. Nested fragments are self-describing, so join needs no schema. A position (aspect root, struct field, map entry value, list element content, enum payload) that has seen several encodings holds one fragment per encoding, joined pointwise (§7).
- A **write** is the smallest unit of authorship: one register value, one element creation, one reset, one flag or position change. Every write carries a **stamp** (§2.2): the commit's timestamp plus the write's **dot**. Writes are never modified, only superseded (later stamp) or pruned (older than a reset).
- A **delta** is a fragment of the same grammar as a state. Applying a delta is `join`. Join is commutative, associative and idempotent, so delivery order, duplication and partial receipt do not matter.
- A **reset** is a stamp stored in a fragment or collection element; every write under it with a smaller stamp is dropped. It is the only removal mechanism. Removal drops writes, and a record left with no write goes (§4.2): a newer insert anchored into removed content is placed at its virtual anchor (§6.1), as at a node that never held that content.
- **Removal is final.**
  - A map entry or list element is **live** while its creation is held and no reset reaches it, and it holds a live value: its creation's, or one written inside it (§4.3, §5.6, §5.7).
  - An enum payload shows only while its case is current (§5.4).
  - A write into an element a reset reached stays in the state, hidden, until a reset prunes it. It never shows the element again; only a new creation (a fresh dot) does.
  - At a position (a register, a struct's field, an aspect root) the later write wins: one concurrent with a reset there shows if its stamp is at or above the reset's (§4.2).
- **Read** is a deterministic function from state to an osis value (spec/data-model.md). Apps see only reads.

## 2. Stamps, dots, sources, clock

### 2.1 Sources and dots
A **source** is who minted a run of counters:
- `Commit(id)`: the commit itself (32-byte commit ID). Counters are per commit, contiguous from 1 across all the commit's deltas (aspects get disjoint ranges). The header marks the form once per commit; a commit uses one form for all its writes.
- `Session(tid, nonce)`: a session of author `tid` (an account): 15-byte tid, then a 16-byte nonce. Every node of an account runs its own sessions under the account's tid; the random nonce keeps them apart.
  - **Start.** The node draws the nonce at random at each start. A new start is a new session; two copies of one store running at once, or a copy restored from a backup, are distinct sessions.
  - **Within a run.** A node also begins a new session once one of its session-form writes under the current ones turns invalid (spec/sync.md §9), under a nonce no earlier session of it used.
  - **Use.** Every content write, durable or ephemeral (spec/data-model.md §2), uses the current session. A node also has a second session, begun with each, for its ephemeral writes with an expiry.
  - **Counters** are per (aspect, session), contiguous, starting at 1, never reused within the session, and live in memory only: a session leaves no counter behind.
  - **Attribution.** Its writes belong to author `tid` (attribution, un-merge). A session-form commit carries them as its own writes (spec/commits.md §3), a snapshot as foreign stamps (§8, spec/commits.md §2).
- `Derived(dot)`: synthetic, never written by any writer. Produced only by lattice embeddings (§7) that need several identities out of a single register write with dot `dot`. Counters start at 1. Belongs to the author of `dot` for attribution, frontiers and un-merge.

A **dot** is `(source, counter)`, counter ≥ 1. A dot identifies one write forever (the commit-level writes of a delta share theirs, §2.3), and doubles as the identity of the element it created.

### 2.2 Timestamps and stamps
- `ts` is one unsigned integer: `wall_ms * 2^16 + logical`, `wall_ms < 2^47`.
- **HLC rules.** A node's clock is `max(wall clock, last ts seen)`, the wall clock being its own (spec/sync.md §6), with `logical` incremented on equal `wall_ms`. On receiving a commit the clock advances to the commit's ts. The author tiebreak lives in the dot, not in `ts`.
- **Parking.** A received commit with `wall_ms(ts)` more than `MAX_DRIFT` ahead of the receiver's wall clock is **parked**: kept unjoined and counted as not received (frontiers, §8) until local wall time catches up, then joined normally. A commit the node makes itself is never parked, whoever signs it: its HLC may run ahead of its wall clock.
- **Next stamp.** Every stamp a node holds has a `ts` at most that of a commit it applied (a carried write is stamped no later than the snapshot carrying it, §8). So a node's next commit stamps above every stamp it holds, but for the ephemeral commit that follows a durable one under its `ts` (spec/sync.md §9).
- A **stamp** is `(ts, dot)`. One commit has one `ts`; every write in it has that `ts`. A creation or position write has its own counter, so these are ordered by counter inside a commit; commit-level writes share `lo` (§2.3).
- **Total order on stamps**: by `ts`; then the dot.
  - Dots of `Session` and `Commit` sources order by source kind (`Session` < `Commit`), then source bytes (tid and nonce, commit ID), then counter.
  - A dot `(Derived(d), i)` orders as the sequence `(d.source, d.ctr, i)` against the `(source, ctr)` of any other dot, so an embedded write sorts right after the write it embeds and below every other greater write (§7).
  - Two different writes never compare equal, unless they share a delta's `lo` (§2.3).
- "Later wins" everywhere means this order.

### 2.3 Counter consumption
A delta for one aspect gets the counter range `[lo, hi)` of its writer's source. Two kinds of writes:
- **Commit-level writes** share the stamp `(ts, source, lo)`, the **delta stamp**: register values, resets (fragment and element), deleted-flag writes, enum case writes, presence writes. One commit carries at most one such write per register, so they never need an order among themselves; against the commit's own reset they win by the `>=` rule (§4.2), which is the "reset, then content" shape of a replace.
- **Creations and position writes** each consume a fresh counter in op order, starting at `lo`: element creations (text/list element, set element, map entry, bag contribution) because the counter is the element's identity, and position writes because siblings written by one commit are ordered by counter (§6.1). The first creation of a commit shares counter `lo` with the delta stamp; the two are compared only as a text element's char register, where a flag write wins the tie (§5.7).
- `hi = max(lo + 1, last counter + 1)`: a delta with only commit-level writes still consumes one counter.

A reader checks that:
- every own-source **write** (stamp) in a delta lies in `[lo, hi)`;
- every commit-level write has the delta stamp;
- own-source dots used as element identities or anchors are either in `[lo, hi)` (created here) or below `lo`;
- creations and position writes use distinct counters.

### 2.4 What the commit header provides
- `ts` of the commit.
- Per aspect: `(tid, ak, counter range [lo, hi), delta hash)` as in §2.3, one delta per `(tid, ak)`. Encoding IDs and the sources table are inside the delta (§3.2), not in the header.
- Dot form (commit, or session with its nonce).
- Snapshot marker (§8): a snapshot commit carries only foreign writes and consumes no counters (empty ranges).
- `expires: T` (wall ms), optional, one per commit (§4.7).
- `undoes: commit id` for undo commits (§4.6).
Every other header field (author, actor, retention, purge request, delete keys, signature) is outside merge.

## 3. Wire grammar

All deltas and snapshots are osis canonical CBOR (spec/data-model.md §5). A **delta** is `[nonce, Sources, Commits, Fragment]` (§3.2) with a 16-byte random nonce; it is self-contained, so sealing and rewriting need no header context. The delta hash covers the whole array.

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
Snapshot := [nonce, Sources, Commits, Fragment, Frontiers, Absorbed]   ; snapshot deltas, §8
Sources  := [Source*]                    ; foreign sources, §3.3 rule 1
Source   := bytes(31) | bytes(32) | [Src, ctr]   ; Session tid ‖ nonce | Commit ID | Derived of a dot whose source is Session or Commit
Commits  := [[Src, [[dwall, logical, base]*]]*]   ; §3.3 rule 1
Ts       := uint                         ; §2.2
Src      := uint                         ; index into Sources, 0 = own (session form: the session; commit form: this commit; not stored)
Ci       := uint                         ; commit index: 0 = this commit, i = Commits entry i (flattened)
Dot      := ctr | [Src, ctr]             ; ctr alone means own source
Stamp    := Ci | [Ci, ctr]               ; Ci alone means that commit's base counter (own: lo)
R        := Opt(Stamp)                   ; reset
W        := Opt(Stamp) | [Stamp, false]  ; explicit presence stamp, see §3.3; [Stamp, false]: value-less (§4.7)
Anchor   := 0 | Dot                      ; 0 = HEAD (counters start at 1, so no clash)
Value    := any osis canonical value

Fragment := Register | Bag | Struct | Enum | Set | Map | Seq | Slots
Register := [0, R] | [0, R, Stamp] | [0, R, Stamp, Value]   ; [0, R, Stamp]: value-less write (§4.7)
Slots    := [10, Opt(Register), [Fragment*]]  ; §7: register slot, then non-register slots by ascending encoding id, at least two slots in all
Bag      := [1|2|3, R, W, [Elem*]]           ; Elem as in Set; the value register holds int|float (anything else, only from §7, reads as nothing)
Struct   := [4, R, W, {field_id: Fragment}]          ; or paged: [Link+], §8
Enum     := [5, R, W, Case, {case_id: Fragment}]   Case := Opt([Stamp, case_id] | [Stamp])   ; payload map paged: [Link+], §8
Set      := [6, R, W, [Elem*]]               Elem  := [Dot, R, Opt(Fragment)]
Map      := [7, R, W, [Entry*]]              Entry := [Dot, Opt(Ci), R, Value, Opt(Fragment)] | [Dot, Opt(Ci), R, Opt(Fragment)]   ; Value is the key; omitted: key not carried. Opt(Ci) here is the bare Ci or nothing: the entry's creation commit (§5.6), carried for a creation of another commit than this one
Seq      := [8|9, R, W, [Run*]]
Run      := [Dot, n, Creation, Content, [PosW*], [FlagW*]]
Creation := [] | [Anchor, [[Ci, k]*]] | [Anchor, [[Ci, k]*], false]   ; segments: k consecutive elements created by commit Ci; sum k = n; false: list creations held value-less (§4.7)
Content  := text: string | []                ; list: [Fragment*] | []; a text run carrying no char has [], never ""
PosW     := [i, Stamp, Anchor] | [i, Stamp, Anchor, Stamp]   ; 0 <= i < n; the fourth: the write's sibling key (§5.7), its ts below the stamp's
FlagW    := [i_from, i_to, Stamp, bool] | [i_from, i_to, Stamp, false, string]   ; inclusive range, 0 <= i_from <= i_to < n; the string (text only): an undelete's chars, one per element of the range (§5.7)
```
**Commits** is the delta's table of every commit other than this one whose stamps appear in the fragment. A commit is a `(ts, source)` pair; `Src` 0 entries name the writer's own earlier commits.
- **Order.** Entries are grouped by source in `Src` index order; within a group ascending by `ts`.
- **Fields.**
  - `dwall`: the difference of `wall_ms` to the previous entry of the group (absolute for the first).
  - `logical`: the low 16 bits of `ts`.
  - `base`: the smallest counter among that commit's stamps in this delta, creation stamps named by segments and entry `Ci`s included.
- **Index 0.** Commit index 0 is this commit `(header ts, own, lo)`.
- **Bare stamp.** A stamp encodes as its commit index alone when its counter equals the commit's base, which is every commit-level write (§2.3) and the first creation.
- **Who fills it.** A writer's write stamps are all its own (anchors are dots, not stamps), so its table lists only the commits its sibling keys name (§5.7). The table is populated in snapshots (§8).

**Run** semantics: a run describes elements `e_i` with dot `(first.source, first.ctr + i)`, `0 <= i < n`.
- **With a `Creation`** the run **creates** them. Segment `[Ci, k]` gives the next `k` elements the creation stamp `(ts(Ci), first.source, first.ctr + i)`. `e_0` anchors at `Anchor`, `e_i` (i > 0) at `e_{i-1}`.
- **Without a `Creation`** the run carries writes on elements that exist elsewhere.
- **`Content`** lists, in order, the content of the run's elements that **carry content**:
  - text: the creation's char (one Unicode scalar value) of each element not deleted after the run's `FlagW` are applied (an undelete's char rides its `FlagW`);
  - list: one fragment per element whose fragment is non-empty (§4.2 Emptiness) after the run's `FlagW` (element resets, §5.7) are applied. A list run is uniform in this (rule 3), so a list `Content` is empty or has exactly `n` fragments;
  - `[]` means no content carried for any element (a pure flag or position delta, or, with a `Creation`, value-less text creations, §4.7).
- **`PosW`** are position writes other than the creation write.
- **`FlagW`** are deleted-flag writes for text, an undelete's with the chars it carries, and element resets (`true` only) for lists (§5.7).

**Creation stamps.** A map entry's **creation** is a write with stamp `(ts, entry dot)` (§5.6).
- A record carrying it names its commit by `Ci` right after the dot, except when that is this commit (a writer's own creation: an own-source dot in `[lo, hi)` with a fragment, whose `ts` is the header's).
- So snapshots carry the creation `ts` of every entry they hold whose creation survives, and a writer never writes a `Ci` there.
- A sequence element's creation `ts` is its run segment's commit (§3.2 `Creation`).
- A set or bag element's creation `ts` is its value register's stamp, written only by its creation (§5.5).

**Keys.** Set elements have no key; their value is a `Register` fragment. A map entry record is identified by its dot and its key (§5.6): its creation and nested writes carry the key, each as its own value; a removal carries it only in a role-class aspect (spec/data-model.md §9), else it is the dot's key-erased record (keyless form, §4.7, §5.6).

### 3.3 Canonical rules (byte-for-byte determinism)
1. **Tables.**
   - `Sources` lists foreign sources in order of first appearance in the `Fragment`'s canonical encoding, and nothing else:
     - pages are expanded in place, in link order;
     - list runs are counted as if not closed by content size (rule 3);
     - stamps and dots count alike, as they are encoded;
     - a `Derived` source is preceded by its underlying source.
   - A snapshot's `Frontiers` (§8) name sources of the fragment.
   - `Commits` holds exactly the commits other than this one with stamps in the fragment, grouped and ordered as in §3.2, each with `base` = its smallest counter in this delta.
   - A `Dot` or `Stamp` uses the bare form whenever it can.
2. **Order.**
   - Arrays of elements, entries, runs are sorted by dot (source as in §2.2, then counter).
   - Entries of one dot are sorted by key, the keyless one first, then by the key's canonical encoding bytewise (links by their bytes), each (dot, key) at most once.
   - Exception: a commit-form delta's own source sorts below every other commit ID (its writer encodes before the commit ID exists).
   - `PosW` are sorted by `i`, then stamp descending.
   - `FlagW` are sorted by `(i_from, Stamp)`, ranges never overlapping and maximal (adjacent elements with the same flag write, both carrying a char or neither, are one range).
   - Segments are in element order with adjacent equal `Ci` merged.
   - Maps sort by canonical key bytes as all osis maps do.
3. **Runs** are maximal, up to `MAX_RUN` elements per run.
   - A creation run extends over consecutive dots of one source as long as:
     - each element's creation write exists in the state;
     - `e_i` was created anchored at `e_{i-1}`;
     - "carries something" (text: deleted flag `true` or has a char; list: has a reset or a non-empty fragment) and, for lists, "has a non-empty fragment" and "held value-less" are the same for all.
   - A non-creation run extends over consecutive dots that all have no creation write, no position writes, the same deleted write or element reset, and the same "carries something" and, for lists, "has a non-empty fragment".
   - Runs are formed first. A list run is then cut into consecutive wire runs after each element at which the canonical encodings of its `Content` fragments since the last cut (as written, links included) sum to `CHUNK_MAX` bytes or more. Each piece after the first is a creation run anchored at the previous element (or a non-creation run), and a cut does not restart the `MAX_RUN` count.
4. `W` is encoded whenever the state holds a surviving explicit presence write (§4.3). A `Slots` position lists its slots in the order of §3.2 (§7); a position with one slot is that slot, never a `Slots`.
5. A fragment never carries writes already implied by another write in the same delta (e.g. a creation run does not list its creation position writes in `PosW`) or that its pruning drops (§4.2: a delta is prune-stable like a state), and a snapshot never carries content for deleted elements. A creation and its position write are one write: an implied position write that the top-2 of its element's position writes (in a map, of its dot's records, §5.6) leaves out is not dropped, the creation being held. A reader holds a delta as its pruned form.
6. Own-source counters lie in the header range; creations and position writes have distinct counters (§2.3).
7. A reader rejects a delta (bad input, never a panic) on any of the following.
   - **Encoding**
     - non-canonical CBOR;
     - a `Src`, `Ci` or counter out of range or 0 where 1 is the minimum;
     - a non-canonical table order or bare/array form;
     - a fragment whose canonical re-encoding differs from the input (rules 1–5).
   - **Runs**
     - a segment's commit with another source than the run;
     - n = 0 or n > `MAX_RUN`;
     - a list run whose `Content` reaches `CHUNK_MAX` bytes before its last element;
     - a `FlagW` or `PosW` index out of range;
     - a `FlagW` `false` in a list run;
     - a `Creation` marked value-less in a text run;
     - a `FlagW` string on a `true` write or whose length differs from its range;
     - a run carrying no write (no `Creation`, `Content`, `PosW` or `FlagW`);
     - a text `Content` on a run without a `Creation`;
     - a non-empty `Content` whose length differs from the number of content-carrying elements of the run;
     - a `PosW` sibling key whose `ts` is not below its stamp's.
   - **Records**: a set, bag or map entry record carrying no write (no reset, no creation, and a fragment absent or empty, §4.2 Emptiness), as a run carrying none above.
   - **Registers and set or bag elements**
     - a `Register` with a reset below a nested level (only aspect roots and the slots of a `Slots` carry one);
     - a set or bag element whose fragment is not a `Register`, or whose register write has another source than the element's dot (only its creation writes it, §5.5).
   - **`Slots`**
     - a `Slots` in a writer's delta;
     - a `Slots` with fewer than two slots, a non-register first slot, unsorted or repeated slot encodings;
     - a `Slots` slot that is empty or adds nothing to the register's embedding;
     - a `Slots` whose encoding pruning (§4.2, §7) would change (content rule 5 leaves out, such as a deleted embedded character, does not count).
   - **`Derived` sources**
     - a creation run of a `Derived` source in a writer's delta (only snapshots carry embedded characters, §7);
     - a write stamped with a `Derived` source other than a text element's creation and that creation as a position write (§7).
   - **Writer's deltas**
     - in a writer's delta, runs with empty `Content` of more than `MAX_DELTA_BARE` elements in all, pages included.
       - A delete or move of more elements is split across commits; `replace` and `remove_aspect` clear any length with one reset.
     - in a writer's delta, a commit-level write (§2.3: register value, reset, `W`, case, element reset, `FlagW`) whose stamp is not the delta stamp;
     - foreign stamps other than sibling keys in a delta that is not a snapshot.
   - **Map entries**
     - an entry `Ci` in a writer's delta, naming this commit, or naming a commit of another source than the entry's dot;
     - outside a role-class aspect, a keyed map entry record with a reset (§5.6; any delta kind).
   - **Core aspects** (any delta kind): a fragment that does not fit the core schema's type (positions the type does not declare are not judged):
     - a fragment other than a `Register` or `Slots` whose encoding is not its position's;
     - a register value or map key the typed read at its position refuses (spec/versioning.md §5; so a link only where spec/data-model.md §6 allows one);
     - an enum case write naming an undeclared case.
   - **Depth**: a fragment that, with every write it carries live, would read deeper than `MAX_VALUE_DEPTH` (spec/data-model.md §5) from the aspect root:
     - a struct, map or list adds one level, an enum or set two;
     - a register adds its value's depth, a map key its depth below its map;
     - a `Slots` position adds its deepest slot;
     - pages are counted in place.
   - **Prune**: a fragment whose prune (§4.2) would drop a write it carries, or a copy of one (a register's reset below its write, §5.1, included; the records of one map dot prune each other across pages, so a write held in two of them is one copy too many, §5.6).
   - **Size**: a durable delta's root fragment or page over `MAX_PAGE_ITEMS` (§8).

## 4. Join, prune, presence (all encodings)

### 4.1 Join
`join(A, B)` where both are the same encoding: take the union of all writes, keeping for each register the write with the greatest stamp, for each reset the greatest stamp, for each collection the union of elements by dot (joining records of one dot recursively), then **prune** (§4.2). Different encodings: §7. Join of a state with a delta is the same operation; a state is just a fragment with every stamp written in full.

**Copy order.** Two copies of one write (equal stamps; a valid snapshot's copy joins beside the write's own delta's, never compared with it, spec/permissions.md §5.2, so copies may differ) join part by part, each part to the greater. What expiry and purge take from a copy (its key, its value, §4.7) is a part of its own, so it decides no other part:
1. in a map dot's records (§5.6), the key: the greater (canonical encoding, bytewise; the key-erased record's copy carries none, lowest); a map write's key is its own value;
2. the value: a valued copy over a value-less one (§4.7; a `W` or a list creation too), then the greater: a register value by its canonical encoding, bytewise (spec/data-model.md §5, links by their bytes); an enum case by its id; a text char by its scalar value;
3. the rest: a creation or position write by its anchor (`HEAD` lowest, then dot order, §2.2), then a position write by its carried sibling key (none lowest, §5.7); a flag write `true` over `false`, its undelete's char (a value) then taken from the copies of that flag.

A text char is a payload of the write carrying it: the creation's goes with the creation's stamp, an undelete's with its flag write's (§5.7). Copies of one creation under different stamps are one write (§5.7 Join). In a `Slots` position, a text slot's embedded records follow the register's winning copy (§7).

### 4.2 Prune
Every fragment has an **effective reset** `E = max(E_parent, own R)`, with `E_root = own R` and `-inf` where none. A write with stamp `s` survives iff `s >= E`. Equality means the write and the reset come from the same commit (a replace: reset and content share the delta stamp, §2.3; embeddings §7 do the same), and then the content wins. Rules per structure:
- Registers: the write is dropped if `s < E`.
- Composites: the presence stamp (§4.3) is dropped if `< E`; children are pruned with `E` as their parent reset. A nested fragment's own `R` below `E_parent` is dropped like any other write.
- Collection elements:
  - The element's own `R` survives iff `>= E_parent`; its content is pruned with `E_elem = max(E_parent, R_elem)`.
  - **A record with no surviving write goes**, in every collection: a set, bag or map element record whose content is entirely pruned and whose own `R` is dropped, and a sequence element record left with no creation, position, flag or content write. What anchors at a sequence record gone is placed at its virtual anchor (§6.1), as at a node that never held it.
  - One whose content is pruned but whose `R` survives is a **tombstone** (dot plus reset stamp, nothing else).
  - A text element's flag write below its surviving creation is dropped: the creation beats it (§5.7).
- **Emptiness.** A fragment is empty iff it holds no surviving write at any depth.
- `Slots` positions (§7) have one effective reset `E = max(E_parent, greatest slot reset)`; every slot is pruned under it, so a slot's own reset below it goes.
- A delta, after pruning against the state it joins, may contribute nothing.

### 4.3 Presence
- A register is present iff it holds a surviving valued write (a value-less winner, §4.7, is absent).
- A composite (bag, struct, enum, set, map, seq) has a **presence stamp** `written`: the greatest stamp among all writes inside it, plus any explicit `W` write. It is present iff `written` survives (`written >= E`).
  - **Counted**: its children's writes, element creations (a map entry's: the keyed record's, §5.6), element resets, nested resets, case writes, position and flag writes.
  - **Excluded**: its own reset and value-less writes (§4.7).
  - **Sequences**: a creation counts iff it is valued (text: its char is held; list: not held value-less) or the element has a flag write (text: a deleted char is never on the wire, an undelete carries its own) or is reset (list).
  - `written` is a function of the surviving writes; only explicit `W` writes are stored, so expiry can lower it.
- A fragment **holds a live value** iff it is a register whose write is valued, an enum whose case write is valued, a composite with a valued `W`, a set or bag with a present element, a map with a live record (§5.6), a sequence with a live element (§5.7), a struct one of whose fields holds one, or a `Slots` position whose chosen slot (§7) holds one. Resets, flags, positions and value-less writes are none.
- An aspect is present on a thing iff its root fragment is present. `aspects.0` reads the present ones.
- A writer emits an explicit `W` (a commit-level write at the delta stamp, §2.3) only when creating or replacing a composite with no content writes in the same delta (an empty set, an empty struct). `W` is a write like any other for frontiers and un-merge, and is always carried on the wire while it survives (§3.3 rule 4).

### 4.4 Read
Defined per encoding in §5. Reading a fragment that is not present yields "absent"; inside a struct that is a missing field (reader default or typed-read error, spec/versioning.md §5); inside a map entry or list element it means the element is not live.

### 4.5 Writes an op produces; a commit is a net effect
Local ops are resolved against local state at write time (index paths, keys, values become dots), so a removal names only observed dots. They produce one delta per touched aspect; sections 5.x list each op's writes.

A delta is a state fragment, so a commit carries the **net effect** of the ops batched into it, not their history:
- A register written twice carries the last value.
- All deletions of one commit are one flag write (the delta stamp).
- An element created and removed within the same commit is omitted once no other write of the commit anchors at it (chained creations, position writes of moved elements), repeatedly, so a removed chain goes whole.
- One still named stays, since re-anchoring what names it would reorder it among the anchor's other children (stamps do not change): a list element with its element reset, a text element as its creation without its char (a flag of the commit, at the delta stamp, would lie below the creation and lose to it, §5.7).

### 4.6 Undo and un-merge (of invalid deltas)
An **undo commit** sets `undoes` (spec/commits.md §7). Its deltas are ordinary writes the undoing node chooses; a receiver judges it like any content commit (spec/permissions.md §5.2) and never derives its writes again. The undoing node:
- MUST hold the rights any write of the same deltas needs (write on each thing it deletes or brings back, the required role on every aspect it writes), else there is no undo; likewise for ephemeral undo and redo.
- MUST NOT write back content it holds value-less (§4.7: expired by the undo's `wall_ms(ts)`, named by a purge request it holds, an ephemeral write it no longer holds), nor content outside kept history (spec/commits.md §7).
- MUST give the commit an expiry no later than that of any write whose content it writes back (a receiver does not check it: writing a value back is writing it again), and MUST NOT write back in one commit the content of writes that expire at different times (no expiry counting as one): such an undo is refused until the sooner ones have expired.
- SHOULD make each aspect the undone commit wrote read as it did just before that commit, as kept history gives that state (spec/commits.md §7), where only undo commits changed it since. Undoing a thing's creation so deletes the thing (its durable aspects reset as a delete resets them: each one present, or written by a valid part not received yet that no held root reset stamped after it covers; its ephemeral state dropped locally as a delete drops it (spec/sync.md §9 Sending), its memberships removed in the groups the node may write).
- MUST NOT undo a delta whose inverse **restores** replaced content unless every part it may have replaced is kept (spec/commits.md §7). Judged by the delta's writes alone: it restores when it holds a register write, a case write, a reset, an element or record removal, a sequence position or flag write, or such a write nested in a record it did not create; taking away its own creations (a sequence insert, a set or bag element, a map record, with all nested in them) restores nothing.

Writes of deltas the node judges invalid are not undone. A signal delta is written back as nothing: a signal reads absent before it (spec/commits.md §7). Redo is an undo of the undo commit.

**Un-merge** (revocation, spec/permissions.md §5): the state after un-merging is the join of every body the node holds for the aspect, leftovers (§4.7) included, with the writes of invalid deltas removed.
- **Removed.** The writes of invalid deltas are removed from each delta body, the records they created and others' writes nested in them included. A write belongs to a delta as in §4.7, `Derived` dots to the delta of the underlying dot.
- **A valid snapshot's copies** of those writes stay (spec/permissions.md §5.2), so the state holds the snapshot's copy alone, with whatever payload it carries, and from the snapshot's body only what sits under such a dot without a write of the snapshot's there goes.
- **Records a valid snapshot holds.** A record a valid snapshot holds, by its creation's copy or by the record alone, stays with the valid writes nested in it, whichever body carries them (the record is in the state, so writes into it count).
  - A record is held by its dot, wherever in the aspect the snapshot holds it: the records of a map dot are one entry (§5.6), whatever their keys, key-erased (§4.7) included; also one whose creation a reset pruned there, kept by a later nested write though not live.
- **Function of the held set.** The result is a function of the held set, never of the order in which the commits and the revocation arrived. A body dropped as covered is held through its valid coverers' copies (spec/commits.md §5); once no valid coverer carries it, it is missing again (spec/permissions.md §5.2) and, until a copy arrives, the node holds less of it than one that kept it.
- **Seq elements** created by an invalid delta lose their creation (anchor and char) with their content; others' position and flag writes on them stay (an undelete's char with its flag write), and a record left with no write goes (§4.2). Such an element is placed by valid writes alone: with no record left, what anchors at it sits at its virtual anchor (§6.1), so the order, like every read, is a function of the valid writes held.

**Un-merge of an ephemeral commit** (revoked author, spec/sync.md §9): the aspect is rebuilt from the node's own writes and the valid held parts left. The commit's writes and records go, as at a node that never held it (what anchors at them sits at virtual anchors, §6.1).

### 4.7 Expiry and value-less writes
A delta with `expires: T` (header, per aspect; `T > wall_ms(ts)`, else the commit is rejected) carries the writes of its source with a counter in its range (commit form: every write of its source in that aspect).
- **Value-carrying** writes are register values, enum case writes, `W` (the value "an empty composite"), set and bag element values, map writes (each carries its record's key as its own value; a creation's is the entry's key, §5.6) and sequence element creations (the text char, the list element). An undelete's char is its flag write's own value (§5.7). A delta's other writes (resets, deleted flags, position writes) carry no app data.
- **Attribution** is by dot: a write belongs to the delta whose range holds its dot (a `Derived` dot to the delta of its underlying dot); an element's or entry's creation to the delta of the element's dot.

Rules:
- **Value-less writes.** A value-carrying write may be held without its value: stamp kept, value gone.
  - **Join**: the copy with the value wins over the copy without (§4.1 copy order).
  - **Read**: a value-less write takes part in "later wins" like any other but reads as absent:
    - a register whose winner is value-less is absent;
    - an enum whose case winner is value-less is absent and its payloads stay hidden until a reset sweeps them (§5.4);
    - a value-less `W` makes nothing present;
    - a set or bag element whose value is value-less is not live; a map entry or list element whose creation is value-less is live only while it holds a live value (§4.3, §5.6, §5.7);
    - a text element whose winning flag write is a value-less undelete is not live (§5.7).
  - **Presence**: value-less writes do not count toward `written` (§4.3).
  - **Map writes**: a map write held value-less sits in its dot's key-erased record (§5.6), so its key goes with its value; the writes of other deltas in the record stay under its key.
  - **Text element**: it keeps its creation write (anchor) and drops its char.
  - **List element**: it keeps its creation write (anchor), held value-less.
  - **Embedded character** (`Derived` dot, §7): it has no creation write apart from the value, so it goes entirely: creation and content. Position and flag writes of others stay, and a record with none of those is dropped (a node that only ever saw the value-less register has no such record either). Anchors at such a dot: §6.1.
- **Expiry rule.** Once a node's wall clock reaches T it holds every value-carrying write of the delta value-less, and strips the value from any copy that arrives later (a stale peer, another copy). It knows T from the commit header, which outlives the body.
  - Its non-value writes stay, and nothing of other deltas goes: expiry of a delta equals the join with that delta's values stripped.
  - Its value-carrying writes are dead at T (§4.8) and its body goes (spec/commits.md §6): the node holds the body's **leftover** instead, the same delta with every value-carrying write value-less, a held body like any other (joined, replayed, covering) that uploads nowhere. So a write that superseded it in the state and is later un-merged does not take it along (§4.6). A leftover reveals nothing of a value: stamps, dots, structure, resets, flags and positions only.
  - **Copies.** No held body carries the value of a write the node holds value-less, and none loses a value of a write the node does not but one stripped for a purge that fell, held through the fall with its value-less copies yielding to a valued one (Join; spec/permissions.md §6): a body carrying a copy of one under its dot (a snapshot's) is held as its leftover, those copies value-less, from the moment the node holds that write value-less or the body joins, whichever is later (a held part of a waiting commit keeps its body until its commit applies, spec/commits.md §5). A delta's own writes keep their values there: it is a held body for keep bounds (spec/commits.md §5), and is deleted at hosts as a dropped body with live writes (spec/sync.md §7).
  - A node holding a valid purge request treats the value-carrying writes it names the same way from the moment it applies it (spec/commits.md §5).
  - Limit: a node that never held the delta's body (gone at hosts at T, spec/commits.md §6) holds others' writes into its entries and elements without their creations, so they do not show there until a snapshot carries the creations value-less (spec/sync.md §7).
- **Snapshots** carry the delta's value-carrying writes value-less (§8; its map writes key-erased), before and after T, and cover it only once none of its values lives (spec/commits.md §5). Before T a node holding the snapshot but not yet the delta reads those writes as absent, like any partial receipt.
- **Ephemeral data** (spec/sync.md §9) follows these rules as durable data does; its leftovers are held in memory like its bodies.

### 4.8 Death of a write
A write is **dead** at a node once the join has superseded it:
- pruned by a reset (§4.2), a register's reset implied by its later write (§5.1) included;
- beaten as a register, case, flag or position winner by a greater stamp;
- its element deleted or tombstoned;
- its value gone by expiry (§4.7).

**Which write.** A write is its position, kind and stamp, never its stamp alone (one op stamps many writes: every value of a map set). Positions: a struct field, an enum payload, a set or bag element, a map entry by its dot (the dot's records are one entry, §5.6), a sequence element per element (a range record is one per element), and the content of an entry or element, below that one's own writes; a `Slots` position's slots are one position (§7). A fragment's **winning writes** are the writes it holds but:
- of a sequence element's position writes only `cur`, when it is not the creation's own (`prev` is beaten);
- not a text element's creation while its winning flag is a delete, but for an embedded char (§7), which dies with its register's write;
- of a map dot's records, the writes of their join (a write beaten at its position by one in another record of the dot is beaten).

A write of fragment `A` is dead in `A ⊔ B` iff it wins in `A` and not in `A ⊔ B`.

**When.** It dies at the earliest `ts` among the valid writes the node holds that supersede it, or at T by expiry (which dates no body, spec/commits.md §5).
- Each is judged against the write alone, so the order of arrival does not matter; a write is held while any held body holds it (its own commit, or a snapshot carrying it).
- A write's `ts` is its own commit's, also when a snapshot carries it: a valid snapshot's copy of a write whose own delta is held invalid counts as the write itself.
- A text element's creation dies only by a delete stamped after the latest undelete of the element the node holds.

**Revival.** Un-merge (§4.6) is the only way a dead write revives.
- The invalid deltas' writes supersede nothing, so a write only they superseded has no death.
- A valid write un-merged with the record it sits in still dies at a valid superseder (a reset on that record).

**Hidden writes.** A write hidden in an element that is not live (§5.6, §5.7 Live) is not dead by that: it dies when a reset prunes it, a compacting writer's sweep included (spec/sync.md §7).

Retention judges when a body was replaced from the bodies a node holds, never earlier than this (spec/commits.md §5).

## 5. Encodings

Each encoding below gives: state, delta shape (= grammar of §3.2, restated where helpful), join specifics beyond §4.1, read, ops, tombstones. Notation for op deltas: `D` is the delta stamp (bare `0` on the wire), `k, k+1, …` fresh counters (§2.3).

### 5.1 Register (0)
- State: `R`, optional write `(stamp, value)`. Nested registers (struct fields, enum payload leaves, set element values) never carry their own `R` (always `[]`); only an aspect whose root is a register uses it, and the register slot of a `Slots` position may (§7). An `R` below the write's stamp is dropped: the write resets everything older at the position (§7), so it implies `R`.
- Join: greater stamp wins. Prune per §4.2.
- Read: the value.
- Ops: `set v` → `[0, [], D, v]` = `[0, [], 0, v]`. `remove_aspect` (root) → `[0, [D]]`, written whatever the state holds. `replace v` (root) → `[0, [D], D, v]` (reset and content share the delta stamp; content wins by `>=`).
- Tombstones: none; the reset stamp is the whole removed state.

### 5.2 Bags: counter (1), max (2), min (3)
- State: `R`, `written`, elements `{dot: (R_elem, value register)}` exactly as a set (§5.5); the register holds the contribution amount (int or float per the aspect type). The register's first write has the element's creation stamp.
- Join: as set; prune.
- Read (bit-identical on every node):
  - Counter: the sum of live contributions.
    - Ints are summed exactly and the sum clamped to i64 (never a panic).
    - Floats are summed as f64 in dot order (§2.2): the float sum starts at +0.0 and adds each float in dot order.
    - A bag holding both (only via §7) reads as float sum plus int sum: the float sum, then the int sum converted to f64.
  - Max/min: the extreme under this order: int against int by value, anything involving a float by IEEE 754 totalOrder on f64 (-0.0 < 0.0, the canonical NaN greatest). Among equal extremes, the one with the lowest dot. They fold in dot order, replacing the running extreme only when strictly greater (less).
  - Absent when nothing is live and `written` does not survive. Max/min with no live contribution reads absent, counter 0.
- Ops: `inc(a)` → one element `[k, [], [[0, [], D, a]]]`. Contributions that are not numbers (only from a register embedding, §7) are ignored by read. `set v` (a replace) → fragment reset `D` then one element `k`. For max/min a bare contribution is "observe v".
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
- Tombstone lifetime: until the set fragment is reset (`R_elem` is pruned like any write below `E_parent`). Until then it drops a late-arriving older add. No other GC.

### 5.6 Map (7)
- State: `R`, `written`, entry records `{(dot, key): (R_rec, creation, fragment)}`, plus a local index `key -> live records` (not part of the lattice).
  - A record's key is part of its identity; each write in a record carries the key as its own value (§4.7).
  - A dot's **key-erased** record `(dot, -)` holds the dot's writes held value-less (§4.7), and its removals outside role-class aspects.
  - The records of a dot are one entry (§4.8 Which write).
- Join: union by `(dot, key)`; per record `R` max, fragment join, creation by stamp; then prune:
  - every record of a dot under `E_rec = max(E_parent, every R_rec of the dot)`: every reset of the dot reaches each of its records;
  - each write of the join of the dot's records (§4.8 Which write: a nested entry too is its dot, whatever its records' keys) sits in one record, the one carrying the greatest key of its copies (the key-erased record's lowest), as the join of every copy (§4.1 copy order), and no record holds another write: the dot's greatest `R_rec` and creation, and of the records' fragments (pruned under `E_rec`) what their join holds;
  - the creation `(ts, dot)` is a write of its own, pruned like any other (under `E_rec`), and a record holding only it (its content un-merged, §4.6) stays, on the wire as `[Dot, Ci, R, key, []]`;
  - tombstone = a record left with only its `R_rec`; a record with no write goes.
- **Removal**:
  - In a role-class aspect (spec/data-model.md §9, keys are public ids) a removal of record `(dot, k)` is `(dot, k, R)`.
  - In every other aspect it is `(dot, -, R)`, so a key never outlives its entry's content in a removal or tombstone. A keyed record with a reset outside a role-class aspect is malformed (§3.3 rule 7).
  - Either resets every record of the dot.
- **Live**: a keyed record whose dot's creation is held (in it, valued, or value-less in the key-erased record), and whose content, its fragment joined with its dot's key-erased record's fragment, is present and, but under its own valued creation, holds a live value (§4.3).
  - A removal prunes the creation, so a nested write newer than the removal leaves the record not live: it stays, hidden, until a reset prunes it, and only a new entry (a fresh dot) shows the key again.
  - A live record reads as its fragment joined with its dot's key-erased record's fragment.
- Read: for each key with at least one live record, `read(join of the live records' reads)`. Two live records with one key (concurrent puts) read as one merged value; with equal links as keys (spec/data-model.md §6) the read shows the key of the lowest live record in dot order (§2.2), then key order.
- Ops:
  - `put(key, v)`: if a live entry with that key exists, write `v` by structural diff (against the key's read, the join of its live entries) into the **lowest live dot** (lowest in §2.2 dot order) and leave the others alone; else create `[k, [], key, [fragment of v]]`.
  - `remove(key)`: the reset stamp `D` on every live record of that key, as the Removal rule above says (`[dot, [D], key, []]` in a role-class aspect, else `[dot, [D], []]`).
  - `set_field` and other path ops into an entry go to the lowest live dot. With no live entry of that key:
    - an op whose remaining path is empty or starts with a key creates one, `[k, [], key, [the op's writes against an absent fragment]]` (an op that writes nothing creates nothing; concurrent creations of one key are two entries read as their join);
    - an op whose remaining path starts with a field or case is refused (it would create a partial struct or enum).
  - `replace` of the map: fragment reset then puts.
  - `put_new(key, v)`: create `[k, [], key, [fragment of v]]` whatever is live (a concurrent put's shape: the delta carries `v` whole and resets nothing). At a register position other than a map key, `put_new` writes the register with no reset (even when equal). At any other position it is refused.
- Tombstones: an older nested write is dropped by the tombstone. Map tombstones live **until the map fragment is reset** (then every tombstone older than the reset is itself pruned). No other GC.

### 5.7 Sequences: list (8) and text (9)
Text is `list<char>` with run compression and immutable element content; list elements carry a recursive fragment. The two differ in how an element is removed: text by a **deleted flag**, list by an **element reset** (a concurrent newer nested write survives in the state, hidden, and does not show the element again, as in maps; spec/requirements.md, Data model).

**State** per element (identity = creation dot):
- `created`: the creation write `(stamp, anchor)`, kept as long as it survives pruning even when two later moves have pushed it out of `pos`. Text content has no stamp of its own: it is present iff `created` is.
- `content`:
  - Text: the char, immutable, held as the creation's value (goes with `created`) and, when the surviving `deleted` write is an undelete carrying one, that write's own value (goes with the flag write, by its own expiry or purge, §4.7). A record without `created` shows no char (Live). A node may drop the creation's char once it holds a flag write (Join keeps none below the creation): no read takes it there (Live), any reset pruning that flag prunes the creation too, and un-merge rebuilds from bodies (§4.6).
  - List: a fragment, joined like any other and pruned under `E_elem = max(E_parent, R_elem)`.
- `pos`: the two greatest position writes `(stamp, anchor, key)` seen (top-2 under §2.2), the creation write included: `cur` and `prev`. Top-2 of a union is the top-2 of the union of top-2s, so this is a lattice. `key`, the **sibling key**, orders the element among its anchor's children (§6.1): the write's own stamp unless it carries one (a creation never does; an undo restoring a position carries the restored write's).
- Text: `deleted`, LWW register of bool; absent means false. Its writes may cover ranges (`FlagW`); an undelete's write carries the char as its own value (above), a delete's never does. With the creation it is one register for the char, by stamp, a flag write winning a tie: the creation's char, an undelete's or none (a delete).
- List: `R_elem`, the element reset (greatest stamp), written as `FlagW true` over a range. `created` is not pruned under it (the anchor stays placed), but **Live** compares them. A list creation may be held value-less (§4.7); of two copies the valued one wins (§4.1).
- **Live**:
  - A list element is live iff `created` is held and above `R_elem`, and its content fragment is present and, under a value-less creation, holds a live value (§4.3). A list element is **deleted** iff it is not live.
  - A text element is live iff `created` is held and either no `deleted` write is held and the creation's char is, or the `deleted` write is an undelete carrying its char; it shows that char. An undelete without its char (value-less, or written without one) hides the element as a delete does, as a value-less register winner reads absent.
- Element existence: a record lives while it holds a write (§4.2); what anchors at a record gone sits at its virtual anchor (§6.1). Text content lives and dies with the creation write: an undelete newer than a reset that pruned the creation revives the flag, not the content.

**Join**: union by dot; per element as below; then prune:
- `created`: one write per dot, so copies under different stamps are copies of it: the greater stamp wins whole (anchor and char) and the lesser is dropped, as a position write too. Between equal stamps, the greater anchor and the greater char (§4.1 copy order).
- List fragment: join.
- `pos`: top-2 by stamp of the position writes and the surviving creation; of copies of one stamp the greater anchor, then the greater carried key, none below any.
- `deleted`: max stamp, then `true` over `false`, then a char over none, then the greater char. A text flag write below the surviving creation goes (§4.2).
- `R_elem`: max.
- An undelete's char is never folded into the creation's copy, and a text char without a creation joins as none: the two are told apart on the wire (§3.2) and in the state.

**Read**: the linearization (§6) of the live elements, mapped to their content (text: concatenated string; list: list of `read(fragment)`).

**Ops** (all resolved against local state; index paths never go on the wire):
- `insert(after: index|HEAD, items)`: one creation run (or several, rule 3) `[k, n, [anchor, [[0, n]]], content, [], []]`, anchor = dot of the element visually at `index` (HEAD for 0). Elements get dots `k..k+n`.
- `delete(range)`: for each maximal run of consecutive dots in the range, a record `[first, m, [], [], [], [[0, m-1, D, true]]]`; the one delta stamp for the whole commit. List: the element reset prunes the elements' content below `D`.
- `undelete(dots)` (text only): same with `false`, each element's char carried in the `FlagW` string (from the state before the undone delete or a clipboard); an element whose char the writer lacks cannot be shown again (Live). A list element is restored by re-inserting its value with a fresh dot.
- The **range** of a delete or move is the slice of the full placement order (deleted elements included, §6.1) from the first to the last visible element of the selection, so deleted and content-less elements inside a selection travel with it; trailing deleted elements stay behind.
- `move(range, after: index|HEAD)`:
  - `roots`: the elements of the range whose chosen parent (§6.2) is outside the range, in visual order.
  - `pred`: the visible element before the range (or HEAD).
  - `outside`: the elements outside the range whose chosen parent is inside it, in visual order (typically the subtree roots of the range's successors).
  - Writes, each consuming a counter:
    1. the `outside` elements **in reverse visual order**, each a position write to `pred`;
    2. root 1 to the destination anchor;
    3. root j>1 to the last element, in placement order, of root j-1's moved subtree (its subtree minus the `outside` subtrees).
  - Interior elements of the range are never rewritten.
- List element edits: `set_field`/nested ops on element i → record `[dot, 1, [], [nested fragment], [], []]`.
- `replace(items)`: fragment reset `D`, then a creation run. Old elements lose every write below `D`, and their records with no write left go. `remove_aspect` is the same without the creation run: the aspect reads absent.

**Tombstones**: a deleted element keeps its record (dot, pos top-2, deleted flag or element reset) until a reset prunes its writes. There is no tombstone compaction.

## 6. Linearization

A deterministic function of state.

### 6.1 Tree and order
- Every element has an **anchor**: `HEAD` or another element's dot. Children of X are the elements whose chosen position write (§6.2) anchors at X, ordered by that write's sibling key (§5.7), **greatest first** (a newer insert at the same anchor goes nearer the anchor; a moved element lands directly after its target, ahead of the target's older children; an undone move puts it back among them where it was); equal keys (copies of one write on two elements, §4.1) by dot ascending.
- The order is the depth-first traversal from HEAD: X, then each child subtree in sibling order. Deleted elements and elements without content are traversed (their children are placed) but not emitted.
- An anchor naming a dot that is no element record in the state is a **virtual anchor**: a node of that dot with no position write (on `END` by its dot, §6.2) and the elements anchored at it as its children, until a record of the dot is in the state. This covers a creation not arrived yet, one of an invalid delta (§4.6), a record whose writes were all pruned (§4.2), an ephemeral record gone with its commit, and a `Derived` record gone with its value (§4.7; the dot is known from `Sources`) alike, so a node that never held a record and one that dropped it place alike.

### 6.2 Choosing a position: cycles
Position writes are rewritten only by moves, so a cycle in the anchor graph contains at least one move edge. Algorithm, run on the whole state (incremental implementations must produce the same result):
1. Every element starts on candidate 0: `cur`. Candidates after that: `prev` (if any), then `END`.
2. While the anchor graph (over the elements and virtual anchors) has a cycle: among the cycle's elements, demote the one whose **current edge has the smallest stamp** (its write's stamp, not its sibling key; equal stamps: the lowest dot) to its next candidate. `END` breaks every cycle, so this terminates.
3. An element on `END` anchors at HEAD with a virtual stamp below every real stamp, ordered among `END` elements by dot ascending; it therefore appears after every real top-level subtree, at the end of the sequence, with its subtree. Virtual anchors (§6.1) have no position write and are on `END` from the start.
The result does not depend on which cycle is found first.

## 7. Encoding slots and lattice embeddings

A position may see fragments of different encodings: an aspect upgraded from `string` to `text` (spec/versioning.md §4), or two schemas claiming one AK (spec/requirements.md, Versioning). The state at such a position is a **`Slots`** fragment: an optional **register slot** plus one slot per non-register encoding seen, joined **pointwise** (same encoding: §4.1; absent on one side: taken). Writers never produce `Slots`; a delta always has one encoding, and the join forms the position.

**Embedding.** The register slot is embedded into every non-register slot: after a join, each slot `X` is `X ⊔ embed(R)`. `embed` is total from a register into every non-register encoding and depends only on the register fragment `{R: r, write (s, v)}`:
| target | embed |
|---|---|
| counter, max, min | reset `max(r, s)`, one contribution element with dot `s.dot` whose register holds the write `(s, v)` |
| text | reset `max(r, s)`; if v is a string, elements with dots `(Derived(s.dot), i+1)` for the i-th char, all stamps `(s.ts, Derived(s.dot), i+1)`, chained from HEAD, content = the chars; otherwise nothing |
| struct, enum, set, map, list | reset `max(r, s)` only |
A register with no write embeds as reset `r` only. A contribution that is not an int or float reads as nothing (§5.2). The edges are total, so a value-less write (§4.7) embeds like its valued copy, except into text: it embeds no chars (an embedded char goes with its value, §4.7).

A text slot's records `(Derived(s.dot), i)` hold, as creation writes and chars, exactly the embedding of the register slot's winning copy of the write with dot `s.dot` (§4.1 copy order): a join replaces any others (other writes on those records stay; a record left with none goes).

**One reset per position.** The effective reset of a `Slots` position is the greatest reset among its slots (and the parent's); prune uses it for every slot (§4.2). So a `replace` or `remove_aspect` in any encoding removes everything older at the position, whatever encoding wrote it, and a register write (an old app's save) is a reset of everything older in every slot plus its content where an edge exists.

**Read.** A `Slots` position reads as its **chosen** slot: the one with the greatest stamp anywhere inside it (resets included), ties by greater encoding id; the position is present iff that slot is. Ops (§4.5, §9) see the position's read and write into the slot of their schema's encoding; a slot not held is the register slot's embedding (Canonical form), or empty without a register slot, and the write creates it.

**Canonical form.** A position with a single slot is that slot, never a `Slots`. A slot is dropped when it is empty or adds nothing to the register slot's embedding (`m ⊔ embed(R) = embed(R)`), so the slots are a function of the surviving writes and do not depend on arrival order. Wire form in §3.2; §3.3 rule 7 for what a reader rejects.

`Derived` dots never go on the wire from a writer, but a new-app insert anchored to an embedded char references `(Derived(s.dot), i)` through the delta's `Sources` (§3.2), and a snapshot of such a text carries them.

There are no other edges.

## 8. Paging (large deltas, states and snapshots)

Principle: deltas, state and snapshots are the same grammar, so any fragment's element arrays and field maps may be replaced by links to **pages**.

- **Grammar extension.**
  - In `Bag`, `Set`, `Map`, `Seq`, the element array may be `[Link+]` (each a LINK-tagged value, spec/data-model.md §5) instead of `[Elem*]`.
  - In `Struct` and `Enum`, the field (payload) map may be `[Link+]` instead of `{id: Fragment}`, each field (its key and value) counting as one element.
  - A page blob is a non-empty canonical CBOR array of elements (`[Elem*]`, `[Entry*]`, `[Run*]`), a non-empty map of consecutive fields, or again `[Link+]` (at most 2 levels: a root of links to pages of links to pages).
- **When.** A fragment is paged iff its element array or field map as plain CBOR (its own elements inline, nested positions as written, so paging is decided bottom-up) would exceed `PAGE_TARGET`. Paging is mandatory above the threshold and forbidden below. An ephemeral commit's deltas (spec/commits.md §2) are never paged: no threshold, each bounded by its blob.
- **Boundaries.** A paged array or map is split into pages at content-defined boundaries over the canonical bytes of consecutive elements (the chunker values use, spec/data-model.md §6; exact rule and link pages: spec/wire.md §6). A page holds whole elements, so one element above `CHUNK_MAX` is a page by itself.
- **Blobs.** Pages are blobs under random keys like chunks (spec/data-model.md §6). A delta links each blob at most once (equal pages are separate blobs), and a reader rejects a delta linking one blob twice.
- **Items per blob.** A durable (not ephemeral) delta's `Fragment` (the fourth item of its root array) and each of its pages and link pages count at most `MAX_PAGE_ITEMS` items:
  - one per CBOR head (each integer, byte string, text string, array, map, tag, `true`, `false` and float; a tag and the item it encloses count separately, a map's keys and values each count);
  - one per byte of each text string's content (a byte string's content counts nothing).
  - A reader counts them from the heads before decoding the blob and rejects the delta above it (a blob that is not canonical CBOR is bad input anyway).
- **Join** of a fragment with links: the reader fetches every page before its commit is applied (spec/commits.md §4) and joins their elements. A page's elements are all keyed by dot, so pages are joined independently, streaming.
- **Snapshot deltas** have the `Snapshot` form of §3.2, with `Frontiers := [[Src, ctr]*]` and `Absorbed := [[bytes(32), tid]*]`.
  - `Frontiers` holds exactly one entry per `Session` source of `Sources` (the sources that **occur** in the fragment: a stamp, an element or entry dot, an anchor or a sibling key names it, value-less writes and tombstones included, §3.3 rule 1), in table order.
  - `ctr` ≥ 0 is the largest counter such that the writer has applied all of that source's writes in this aspect up to it (0: none; parked commits are not applied, §2.2; nor is a delta its commit applied without, spec/commits.md §4, until it joins, unless it has an expiry). The fragment reflects every write in those ranges.
  - Bad input: an entry missing, repeated, out of order, or naming a source of another kind; a snapshot carrying a stamp whose `ts` is above the snapshot's own `ts`.
  - `Commit` sources have no frontier. `Absorbed` (commit ID, then the author as a TID-tagged value, spec/data-model.md §5), sorted by commit ID, lists every commit-form commit whose writes in this aspect the writer had applied and whose source occurs in the fragment.
  - **Absence.** A session or commit-form commit the tables do not name left no write in the fragment: a reader takes its absence for that, never for "not received". An entry of 0 says the writer applied none of the source's writes contiguously, though some of them are in the fragment.
  - Frontiers and `Absorbed` are no receipts (spec/permissions.md §5.1): they serve covering (spec/commits.md §5).
- **Values.** Snapshots never carry the values of writes from deltas with an expiry, expired or not, or of writes named by a purge request the writer holds (§4.7): those writes go value-less, and a delta with an expiry is covered only once none of its values lives (spec/commits.md §5). Live content of any other delta is carried as usual, whatever its retention.

## 9. Structural diff

Input: local state fragment `S` (may be absent), new value `v`, and the writer's **view**: a projection of read values onto what the writer's schema can type (identity for untyped writes). Output: writes, as a delta, with `read(join(S, diff(S, v))) == v`; the edit script is not normative, only:
- **Identity**: an element the script keeps or edits keeps its dot (so concurrent writes into it survive); only elements the script deletes lose theirs.
- Equality compares `view(read(...))` with `v`'s side; an element or entry whose `view` fails (unknown enum case, type mismatch) is **opaque**: never matched, never removed, never re-inserted, and left where it is (spec/versioning.md §5).
- Struct fields present in S but not in `v` are left alone; a field absent in S whose value in `v` equals its declared default gets no write.
- A replace ignores S: fragment reset, then the writes of a diff against absent.
- S is compared as it reads now (§4.7): a value-less write reads as absent, so its position is written again; a value still carried is matched and keeps its expiry, and goes at its T even though the new delta lives longer.
