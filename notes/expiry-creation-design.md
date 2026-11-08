# Expiry and creation records: design
> Summary: Design for issues/expiry-knocks-out-commit.md and issues/creation-record-ordinary.md. Expiry and purge take only a commit's own values; an element shows while it is not removed and holds a live value (its creation's or anyone's inside it); records with no write go (virtual anchors place alike); copy expiry leaves the CRDT (only the undo writer rule stays); `created.0` is an ordinary write whose end ends the thing; writes to unknown things are not kept, only revisited. Decided where Tess's issues decide; marked **Proposal (Tess)** where it needs her.

## Principle
A write's value lives by its own commit: at expiry or purge the commit's values go, and nothing else. Removals, positions and stamps carry no app data and stay. Nothing is judged from data the node does not hold. When it cannot judge, it keeps nothing and fetches again once it can.

## 1. The CRDT rule
**Element rule.** An element (map entry, list element, text char, set or bag element) shows iff:
- it is **not removed**: its creation is held (valued or value-less; for a map, in its keyed record or the dot's key-erased record), no reset at or above it reaches it, and a text char's flag is not a delete;
- its **content is present** (§4.3): for a set or bag element or a text char, the content is its creation's value; for a map entry or list element, its fragment;
- it **holds a live value**: its creation valued, or a valued write anywhere inside it.

The third clause is Tess's rule. Removals (resets, delete flags) are not content, so an expired entry that holds only someone's removal goes. For durable data the third clause always holds, so durable reads are unchanged.

Per container:
- **Map entry.** Each keyed record holds its valued writes, and its key lives while one of them does. A reaction written into another's record is that writer's own write, key included. Value-less writes of any delta sit in the dot's key-erased record, and a live record reads joined with it. Commit 1 (expiring) creates `k` with text and commit 2 adds text: at T, commit 1's creation and text move to the key-erased record, and record `(dot,k)` still holds commit 2's writes, so it shows `k` with commit 2's text. Value-less writes move one at a time, never the whole dot. The "value-less creation hides the dot" rule goes.
- **List element.** A list creation is an anchor and has no value of its own. The element shows while its content holds a valued write. No element reset at T.
- **Text char.** The char is the creation's value, so nothing inside can keep it. An undelete's char is the undeleting write's own value and goes by that write's own expiry or purge.
- **Nested containers.** The rule applies at every depth. An entry's content counts the live values of its nested elements.
- **Registers and cases.** A value-less winner keeps its stamp: it reads absent and still beats older writes. This is the write's implied removal of older values, which stays.
- **`W`** carries a value: it writes the app value "an empty composite". So an expiring `{}` goes at T.
- **Removals and resets.** Unchanged. Removal is final: a newer write inside a removed element stays hidden until a sweep resets it.

**Leftovers at expiry**: only the expired delta's non-value writes: resets, flags, positions, creation stamps with their anchors, and value-less register and case stamps that still win. They are held as the delta's leftover body until a snapshot covers them, as today, because hosts delete the body at T and it cannot be fetched again. Nothing else stays: no element reset, no whole-dot key move, no hidden-dot mark.

**Virtual anchors.**
- *Records with no write.* **Every record with no write goes**, in every collection (built: spec/crdt.md §4.2, notes/crdt.md "Records with no write go"): a seq record left with no write is placed exactly like a virtual anchor (END, by dot, children kept; §6.1-6.2).
- *Expired creations.* An expired creation that no reset has pruned keeps its anchor. That anchor is a non-value write, and others placed content on it in honest flow. Dropping it would move live neighbours to END at T, a visible reorder on a common path (a disappearing paragraph in a durable doc). Invalid writes accept that cost only because they are rare.

## 2. What goes
Copy expiry leaves the CRDT. What remains is §4.6's writer rule: an undo or undelete that copies back an expiring value expires no later, and refuses to mix expiries. Receivers don't check it: copying back is the same as typing the value again.

Removed from the spec:
- §4.7 "Writes into an expiring element" (copy expiry for keys and anchors, the SHOULD for anchoring writes).
- The whole-dot key-erased move, and the distinction between "a value-less copy alone" and "a delta held value-less".
- The list element ending at T, and the snapshot carrying `FlagW true` after T.
- "An undelete's char goes wherever the value goes".
- §4.3's list-content clause (value-less writes count for content).
- §5.6 Live "hides the dot", and §5.7 Live "at `R_elem`".
- The §4.7 Copies rule for expiry. Copies stay only for purge (snapshots carrying a purged write's value), since an expiring value is never valued in a snapshot.

Removed code:
- `write::copy_expiry` and its O(aspect) probe.
- The write path's `Invalid` for copying an expiring value beside lasting ones (notes/api.md Writes; undo keeps its own).
- `Fragment::expire` merges into `strip`, with no `at_node` in `seq::strip_values`.
- The whole-dot move in map pruning.
- `strip_carried` for key repeats and undelete chars.
- The sweep's "creation on the value-less list" clause. The sweep resets records that are removed or not live and still hold a write besides their value-less creation.

Expiry stops changing winners (stamps stay), so it can be an in-place strip of one delta's dots instead of a rebuild.

## 3. Creation records
**Decided (Tess's direction).** No tombstone. A node holds no part whose thing record, chain record or author record it lacks.
- **Throw out and revisit.** Such a part is not kept, and the node remembers only the blob's ID in a per-label revisit set: 32 B, bounded by the host's per-label cap, gone when the entry leaves the host. After any transaction that brings in a record, it fetches those blobs again and judges them.
- **Who holds them meanwhile.** Hosts, under the label, and the author, whose node holds the record and treats its own writes as must-hold.
- **Why it is rare.** First sync already orders creations first (spec/crypto.md order key). Writes before their creation happen mainly when one thing sits under two labels.
- **What this removes.** The pending store for unknown records, the first-copy and junk-slot handling for parts whose hash cannot be checked yet, and the waiting-part-at-expiry and waiting-part-under-purge paths for record waits (`pending.rs` `strip_pending`, `purge_pending` and `emptied` for record waits). It closes issues/pending-unbounded.md for records and the first case of issues/purged-values-in-waiting-copies.md. Other waits (pages, drift, parked, chain edges) could follow the same rule later. This plan does records only.

**Ending.** `created.0` takes ordinary retention: a schema default per AK (proposed `admin`, no history), set per commit like any delta. The fixed `nobody` retention and the commit-sharing exemption go. Purging or expiring it **ends** the thing.
- Every node drops the thing whole, by the existing lost-access path (`retention/forget.rs`).
- Node-sync deletes at hosts what the node has delete keys for, by the dropped-body path.
- A later or concurrent write is a write to an unknown thing: not kept anywhere honest, so "a later write recreates" stops holding only for ended things.
- A disappearing message is one commit.

**What must remain.** Nothing per ended thing at nodes.
- A late write is judged like any write to an unknown thing.
- A purge is proved by its own commit, held by the ordinary purge rules: blobs kept at least `ROLE_KEEP`, and a lasting header when the creation kept history forever. Those are the existing offline-node rules, not a new record.
- An expiry needs nothing: every copy of the creation carries its T in the header.
- Limit, as for any purge: a stale copy that resurfaces after the purge commit is gone brings the thing back with only what is still fetchable.
- Purge is per part: ending one thing leaves the other things in that commit alone.
- Disputes: a side that judges the purge invalid keeps the thing, and hosts keep it while the fork lasts (notes/disputes-plan.md).

**Dependents.** The direction says nothing else depends on records being permanent. That is false in two places: a key actor's record carries the signing key that verifies every commit it signed, and a thing's record chain (validity, waits, derivation) reads its first admin's record. **Decided (Tess): things an ended thing created live on.** Records are identity, `created.0` is existence: A record proves itself by its hash and needs no authority (spec/permissions.md §1). Chain certificates carry raw records, not copies of the creating commit, so the dependents' labels keep the records their chains need. Ending removes the creation write and the thing's data. Things whose first admin ended keep their standing edges, as the direction asks. An ended plain thing leaves nothing. A record is kept only as a dependent's own chain proof.

**`delete`** stays the undoable removal: resets content and memberships, the creation stays live, a later write recreates. Ending is purging or expiring the creation. Name the ending API by notes/api-design.md.

**`required^.0`** keeps fixed retention: later deltas' validity is judged from it, so purging it would change past verdicts. Only its commit-sharing exemption is open, as a spec question.

## 4. Touched issues
- **gap-snapshots-gonemap-differ**: expected fixed by step 3 (no whole-dot move, no hidden dot). Its seeds are step 3's acceptance check. If they still fail, rule out swept-hidden-write-uncoverable first.
- **list-element-snapshot-before-expiry**: moot, because the element no longer ends at T, and showing others' writes is the rule before and after T. Delete it with branch `crdt-leftovers` after step 3.
- **copy-expiry-probe-cost**: the probe goes in step 4. What stays is the per-expiry rebuild cost, narrowed to "strip in place".
- **eph-expired-anchors-fill-cap**: narrowed, stays. Pruned records go (step 1) and expired list elements get no reset, but unpruned expired creations stay as anchors for live neighbours. The fix left is a sweep that re-anchors live children of expired runs, then resets the runs.
- **text-creation-undelete-dating**: unaffected, stays.
- **subgroup-expiry-strands-silently**: stays. An ended group thing strands items the same way, and the same fix (the engine reports at expiry) covers it.

## 5. Requirements wording (needs Tess's sign-off)
- Data model: in place of "A write inside a map entry, list element or enum case shows only while that entry, element or case is live (its creation or case write survives). A write never brings back what was removed, expired or switched away from":
  > A write inside a map entry or list element shows while the entry is not removed and holds content from any write; an expired or purged write takes only its own content. A write never brings back what was removed or switched away from; only a new creation does.
- Deletion, new: "Purging or expiring a thing's creation ends the thing: every node drops it and ignores later writes to it." Plus the dependents choice (A or B) in user terms: "ending an account ends what it created" (A), or "things others also run survive their creator's end" (B).

## 6. Build plan (one worker plus a reviewer each, in order)
Model first: crdt-model for steps 1-3, held-model (its `crdt.rs` liveness, then records and waits) for steps 3, 5-7.
1. **Records with no write go.** Built (models, osis-crdt, engine rebuild stop, spec).
2. **Element rule in the models and spec.** crdt-model, held-model `crdt.rs`, spec/crdt.md §4.3, §4.7, §5.6, §5.7.
   - Property: expiry of X equals the join with X's values stripped (no reset), so it commutes with join.
   - Tests: Tess's three cases (commit 2 lasting, none, expiring later) for map, list and nested; removal-only goes at T; a durable entry emptied by removals stays; a value-less creation from a snapshot before T reads like after T.
   - **Open (blocks the map part).** With per-write key moves the property fails unless a dot's records prune each other at every depth, a rule §1 does not state (spec/crdt.md §5.6 today: "each record keeps its own"). Example: X (expiring) creates `k` with field `a = 1`; Y (lasting) later sets `a = 2` in `(dot, k)`, where the join drops X's `a`. Stripping that state leaves `(dot, -)` with X's creation only; joining X's leftover with Y's body leaves `(dot, -)` also holding X's value-less `a = 1`, beaten by Y's write in the other record. Reads agree, states and snapshots do not, so neither an in-place strip nor convergence of states holds. The same goes for X's nested resets moving out of `(dot, k)` (they stop pruning older writes arriving there). Candidate: a record keeps only its writes that survive in the join of its dot's records. Lists, text, registers and `W` need no such rule.
   - Step 2 also breaks osis-crdt's "strip/expire equals the model" lockstep and the order oracles' list-expiry cases until step 3 lands, so steps 2 and 3 merge together.
3. **Element rule in osis-crdt.** `strip` only, per-write key moves, liveness, `W` as value, undelete char as own value; lockstep against step 2.
   - Gate: the gap-snapshots seeds and `order::arrival_order_list_expiry_*` pass.
4. **Engine: copy expiry goes.** Remove `copy_expiry` and the write refusals; narrow `strip_carried` to purge; adjust the sweep clause; update API notes.
   - Property: a write into an expiring entry keeps its own expiry, and expiry changes only the expiring commit's values.
   - Tests: the osis-API examples (a reaction outlives a disappearing message; a removal does not); the order oracle.
5. **held-model: records as writes.** A thing exists while its `created.0` is held live; parts on unknown things are not held; ending forgets the thing; purge and expiry of `created.0`.
   - Property: the read is a function of the held set in every arrival order of creation, writes, purge and expiry.
6. **Throw out and revisit** in osis-engine and node-sync; remove the record-wait pending paths.
   - Property: creation-after-writes reads like creation-first.
   - Tests: a two-label arrival-order case; pending bytes bounded per label at n and 10n.
7. **Ordinary `created.0` retention and ending.** Spec, commit validation, API: one-commit disappearing message, end by purge.
   - Tests: the thing is gone at every node at T or at the purge, in any order; a write after the end is ignored; a non-admin purge falls; hosts drop the ended thing's blobs.
8. **Dependents** per Tess's A/B choice (B: raw-record chain certificates). Waits for her decision; steps 1-7 don't need it except to refuse ending a key actor meanwhile.

**Positions at expiry and purge (Tess).** Expiry and purge keep an item's bare position, so live items placed after it stay put (unlike an invalid write, which leaves nothing). If keeping positions turns messy for complexly edited text or lists, weak expiry and purge support there is acceptable: prefer the simple rule over a carve-out.
