# Expiry and creation records: design
> Summary: Design for issues/expiry-knocks-out-commit.md and issues/creation-record-ordinary.md. Expiry and purge take only a commit's own values; an element shows while it is not removed and holds a live value (its creation's or anyone's inside it); records with no write go (virtual anchors place alike); copy expiry leaves the CRDT (only the undo writer rule stays); `created.0` is an ordinary write whose end ends the thing; a part or commit the node cannot judge is thrown out and fetched again, and what it opened keeps the keys to fetch what judges it. Decided where Tess's issues decide; marked **Proposal (Tess)** where it needs her.

## Principle
A write's value lives by its own commit: at expiry or purge the commit's values go, and nothing else. Removals, positions and stamps carry no app data and stay. A node keeps no part it cannot judge, and keeps what it needs to fetch what judges it: nothing past the pass that fetched it, except the reading-only secrets its boxes open, and it fetches the rest again once it can judge them.

## 1. The CRDT rule
**Element rule.** An element (map entry, list element, text char, set or bag element) shows iff:
- it is **not removed**: its creation is held (valued or value-less; for a map, in its keyed record or the dot's key-erased record), no reset at or above it reaches it, and a text char's flag is not a delete;
- its **content is present** (§4.3): for a set or bag element or a text char, the content is its creation's value; for a map entry or list element, its fragment;
- it **holds a live value**: its creation valued, or a valued write anywhere inside it.

The third clause is Tess's rule. Removals (resets, delete flags) are not content, so an expired entry that holds only someone's removal goes. For durable data the third clause always holds, so durable reads are unchanged.

Per container:
- **Map entry.** Each keyed record holds its valued writes, and its key lives while one of them does. A reaction written into another's record is that writer's own write, key included. Value-less writes of any delta sit in the dot's key-erased record, and a live record reads joined with it. Commit 1 (expiring) creates `k` with text and commit 2 adds text: at T, commit 1's creation and text move to the key-erased record, and record `(dot,k)` still holds commit 2's writes, so it shows `k` with commit 2's text. Value-less writes move one at a time, never the whole dot.
  - **The records of a dot are one entry** (decided): every reset of the dot reaches each of its records, and a record keeps only its writes the join of its dot's records holds, as the copy that join holds (the map clause of spec/crdt.md §4.8 Which write, applied to state); a keyed record's copy of a write carries the key, so the key-erased record's copy yields to it. Without it the strip of a state differs from the join of the leftover: X creates `k` with `a = 1`, Y later sets `a = 2`; X's value-less `a = 1` in the key-erased record is beaten by Y's. Resets reach the whole dot because a keyed reset reaching only its record made the rule order-dependent across a forged second key.
- **List element.** A list creation carries a value, like a map key or a text char: held value-less it keeps its anchor (a bit on the creation, on the wire a `Creation` marked `false`). The element shows while its content is present and, under a value-less creation, holds a live value. No element reset at T. (With no creation value a durable element emptied by nested removals would vanish.)
- **Text char.** The char is the creation's value, so nothing inside can keep it. An undelete's char is the undeleting write's own value and goes by that write's own expiry or purge; an undelete shows the element by that char alone, so one whose char went hides it (as a value-less register winner reads absent), whether or not the node holds the creation's char.
- **Nested containers.** The rule applies at every depth. An entry's content counts the live values of its nested elements.
- **Registers and cases.** A value-less winner keeps its stamp: it reads absent and still beats older writes. This is the write's implied removal of older values, which stays.
- **`W`** carries a value: it writes the app value "an empty composite", held value-less like a register's (`[Stamp, false]` on the wire). So an expiring `{}` goes at T.
- **Removals and resets.** Unchanged. Removal is final: a newer write inside a removed element stays hidden until a sweep resets it.

**Late nodes.** A node that never held an expired or purged creation (hosts drop its body) holds others' writes in the entry without it, so it shows nothing there until a writer compacts and the snapshot carries the creation value-less; nodes that held it show the others' writes. The existing limit for non-value writes (spec/commits.md §5), now met by reactions too.

**Leftovers at expiry**: only the expired delta's non-value writes and its value-carrying writes value-less: resets, flags, positions, creations with their anchors, value-less register, case and `W` stamps. They are held as the delta's leftover body until a snapshot covers them, as today, because hosts delete the body at T and it cannot be fetched again. Nothing else stays: no element reset, no whole-dot key move, no hidden-dot mark.

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
- The sweep's "creation on the value-less list" clause. The sweep resets only records a removal ended that still hold a write: a record not live for want of a value may still show (a valued write arriving), so resetting it would remove others' concurrent writes.

Expiry stops changing winners (stamps stay), so it can be an in-place strip of one delta's dots instead of a rebuild.

## 3. Creation records
**No tombstone.** A node holds no part whose thing record, chain record or author record it lacks, and no part whose author's reach it cannot read.
- **Unjudgeable.** A part is unjudgeable when `thing_wait` says so (thing record, chain record, author's reach). A commit is unjudgeable when its author's or actor's record is unknown. No such bytes are kept past the pass that fetched them.
- **What stays: reading-only secrets.** A box opens with this node's own KEM key, needs no record, and proves itself by what it opens: it is a means to fetch, not a claim (spec/crypto.md Reading-only secrets). Before discarding, the node reads the `secrets.0` boxes of what it opened (`read_pending_boxes`) into reading-only secrets sourced from that commit, within `MAX_READING*`, and never encrypts under them. This is what lets an invited person open a label whose only key is in the grant, while the record that judges the grant sits under that label. They go when the commit's last part applies, it is judged bad, or its last entry leaves (`by_commit` empties, then `forget_unchecked`). A refused box re-reads when the budget frees (`wake_refused`).
- **A whole commit that waits** turns its label entry into `Kind::Awaits { commit, thing }`: no separate revisit set, since the entry table is bounded by what hosts list and this variant is smaller than `Kind::Commit`. An index thing → entries spans labels. `thing` names what is awaited broadly enough that ending's account signing can name an epoch's minting rotation.
- **A part of an applied commit that waits** keeps its slot in `m.missing`, the awaited thing derived from the held header (`Changed::undropped`, `reopen_undropped`). `settled_slots` does not count those slots; the index is derived from the header, no stored ID.
- **Wake at pass end.** Entries whose awaited record arrived reopen, a commit thrown out whole by any one of its parts' records (the entry names only the first; a part on another thing applies when its record comes); reach waits reopen on moved edges, batched per pass; every awaiting entry reopens when this node's epochs move (`Core::secrets_moved`: also when a reading-only secret only becomes checked, no count changes then and a box opens through it), since a section no secret opened may open now. A refetched blob is judged afresh and may await the next record.
- **One batch per pass.** A pass judges the order-0 fetch together: `created.0` carriers, then role commits by `ts` (as `reexamine` sorts); it discards only what is still unjudgeable at pass end. Otherwise a first sync is a storm of waits.
- **Inbox.** `admits`, `vet_inbox_hints`, `boxed_by`, `hint_actors` ask "applied, or an entry held", not "applied or pending". `hint_actors` reads `inbox_opened`. The inbox blob stays local under `INBOX_WAITING*`, so retrying costs no download. Stamping treats an awaiting commit as it treats a pending one.
- **Ephemeral commits** are thrown out by the same rule. An `Awaits` entry is `memory: true`, charged to the label's memory cap; past it, `refuse_memory`.
- **What stays pending.** `with_pending`/`redeliver` remain for `WaitBlobs`, `Drift`, `Parked` (issues/pending-unbounded.md covers those). A commit carrying its author's `created.0` keeps its aspect list inline (writer rule), so no linked header needs the record it carries.
- **Stated limits.** An insider can exhaust the reading budget and delay honest grants until its entries leave. A commit that expires or whose body is deleted while it awaits is treated as if it never arrived (spec/commits.md §4): a node holds no bytes to flag it from. A hostile writer with a k-aspect blob can cause k refetches by publishing k records one at a time.
- **Rejected.** The grant bringing the record: it removes only the first wait, the author's chain is the same problem next, and it misses the home-label sibling route. Keeping commits with boxes for this node: bytes keyed on an unverified claim any depositor can add.

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
- **expiry-rebuild-cost**: the copy-expiry probe went with step 3; the per-expiry rebuild stays (could strip in place).
- **eph-expired-anchors-fill-cap**: narrowed, stays. Pruned records go (step 1) and expired list elements get no reset, but unpruned expired creations stay as anchors for live neighbours. The fix left is a sweep that re-anchors live children of expired runs, then resets the runs.
- **text-creation-undelete-dating**: unaffected, stays.
- **subgroup-expiry-strands-silently**: stays. An ended group thing strands items the same way, and the same fix (the engine reports at expiry) covers it.

## 5. Requirements wording (needs Tess's sign-off)
- Data model: in place of "A write inside a map entry, list element or enum case shows only while that entry, element or case is live (its creation or case write survives). A write never brings back what was removed, expired or switched away from":
  > A write inside a map entry or list element shows while the entry is not removed and holds content from any write; an expired or purged write takes only its own content. A write never brings back what was removed or switched away from; only a new creation does.
- Deletion, new: "Purging or expiring a thing's creation ends the thing: every node drops it and ignores later writes to it." Plus the dependents choice (A or B) in user terms: "ending an account ends what it created" (A), or "things others also run survive their creator's end" (B).

## 6. Build plan (one worker plus a reviewer each, in order)
Model first: crdt-model for steps 1-3, held-model (liveness through crdt-model, then records and waits) for steps 3, 5-7.
1. **Records with no write go.** Built (models, osis-crdt, engine rebuild stop, spec).
2. **Element rule in the models and spec.** Built (branch `expiry-2`): crdt-model `element_rule_spec_4_7`, `map_dot_records_one_entry_spec_5_6`; held-model; spec/crdt.md §4.3, §4.7, §5.6, §5.7.
3. **Element rule in osis-crdt.** Built with step 2: one `strip`, per-write key moves, a dot's records one entry, list creations and `W` value-carrying, undelete char as own value; lockstep against step 2 (states and stripped snapshots' bytes).
4. **Engine: copy expiry goes.** Built: the write path's `copy_expiry` and its refusals and the sweep clause went with step 3; `strip_carried` handles snapshots alone.
   - Property: a write into an expiring entry keeps its own expiry, and expiry changes only the expiring commit's values.
   - Tests: the osis-API examples (a reaction outlives a disappearing message; a removal does not); the order oracle.
5. **held-model: records as writes.** Built (`spec_records.rs`, `DropWhy::Unknown`/`Ended`, `Outcome::revisit`/`ended`). A thing exists while its `created.0` is held live; parts on unknown things are not held; ending forgets the thing; purge and expiry of `created.0`.
   - Property: the read is a function of the held set in every arrival order of creation, writes, purge and expiry.
6. **Unjudgeable parts.** Built: held-model `fetch.rs`, osis-engine (`Ingested::Awaits`, `apply/waits.rs`), node-sync (`Kind::Awaits`, `wake_awaiting`), spec/.
   - Property: a valid grant whose label is reachable reads like creation-first; forged boxes never change a read.
   - Tests: invite with the record unknown and only the grant's keys open the label; the home-label sibling copy route; a forged grant fills only the budget; an order-0 batch at n and 10n counts no refetches; awaiting bytes per label at n and 10n (the bound covers record and chain waits only: `Drift`, `WaitBlobs`, `Parked` remain, issues/pending-unbounded.md).
7. **Ordinary `created.0` retention and ending.** Spec, commit validation, API: one-commit disappearing message, end by purge.
   - Tests: the thing is gone at every node at T or at the purge, in any order; a write after the end is ignored; a non-admin purge falls; hosts drop the ended thing's blobs.
8. **Dependents** per Tess's A/B choice (B: raw-record chain certificates). Waits for her decision; steps 1-7 don't need it except to refuse ending a key actor meanwhile.

**Positions at expiry and purge (Tess).** Expiry and purge keep an item's bare position, so live items placed after it stay put (unlike an invalid write, which leaves nothing). If keeping positions turns messy for complexly edited text or lists, weak expiry and purge support there is acceptable: prefer the simple rule over a carve-out.
