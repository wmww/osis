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
- **Wake at pass end.** Entries whose awaited record arrived reopen, a commit thrown out whole by any one of its parts' records (the entry names only the first; a part on another thing applies when its record comes); reach waits reopen on moved edges, batched per pass; every awaiting entry reopens when this node's secrets change, or a reading-only one becomes checked (a box opens through it; no count of secrets changes then), since a section no secret opened may open now. A refetched blob is judged afresh and may await the next record.
- **One batch per pass.** A pass judges the order-0 fetch together: `created.0` carriers, then role commits by `ts` (as `reexamine` sorts); it discards only what is still unjudgeable at pass end. Otherwise a first sync is a storm of waits.
- **Inbox.** `admits`, `vet_inbox_hints`, `boxed_by`, `hint_actors` ask "applied, or an entry held", not "applied or pending". `hint_actors` reads `inbox_opened`. The inbox blob stays local under `INBOX_WAITING*`, so retrying costs no download. Stamping treats an awaiting commit as it treats a pending one.
- **Ephemeral commits** are thrown out by the same rule. An `Awaits` entry is `memory: true`, charged to the label's memory cap; past it, `refuse_memory`.
- **What stays pending.** `with_pending`/`redeliver` remain for `WaitBlobs`, `Drift`, `Parked` (issues/pending-unbounded.md covers those). A commit carrying its author's `created.0` keeps its aspect list inline (writer rule), so no linked header needs the record it carries.
- **Stated limits.** An insider can exhaust the reading budget and delay honest grants until its entries leave. A commit that expires or whose body is deleted while it awaits is treated as if it never arrived (spec/commits.md §4): a node holds no bytes to flag it from. A hostile writer with a k-aspect blob can cause k refetches by publishing k records one at a time.
- **Rejected.** The grant bringing the record: it removes only the first wait, the author's chain is the same problem next, and it misses the home-label sibling route. Keeping commits with boxes for this node: bytes keyed on an unverified claim any depositor can add.

**Ending.** `created.0` takes ordinary retention: a schema default per AK (proposed `admin`, no history), set per commit like any delta. The fixed `nobody` retention and the commit-sharing exemption go. Purging or expiring it **ends** the thing.
- **Who ends** (spec/permissions.md §6): any admin at the request, as with any purge right. Reading the right from standing on the first admin alone is rejected: a removed admin could then destroy a thing for everyone.
- Every node drops the thing whole in the transaction that made its last creation value-less (`retention/end.rs`): incremental, cost the thing's parts, since a disappearing message ends often; the commits' headers stay, as for any purge.
- Node-sync deletes at hosts what the node has delete keys for, by the dropped-body path.
- No wait before hosts delete (Tess): an ending that later falls brings the thing back only if some node still holds a copy.
- A later or concurrent write is a write to an unknown thing: not kept anywhere honest, so "a later write recreates" stops holding only for ended things.
- A disappearing message is one commit.

**What must remain.** Per ended thing at nodes, only what any purge leaves: commit headers; for an ending by purge also the request's own `purge.0` part and the thing's record that places it for nodes that have not heard (`Core::ended` treats the thing as unknown). An ending by expiry leaves no record unless a dependent needs it (Dependents).
- A late write is judged like any write to an unknown thing.
- A purge is proved by its own commit, held by the ordinary purge rules: blobs kept at least `ROLE_KEEP`, and a lasting header when the creation kept history forever.
- An ending by purge keeps what judges it for good, since nothing drops a request: the thing's record, value-less creation and `roles.0` parts (no content), so a removal arriving later can make it fall and a stale copy is ended again. Any admin at the request may end, as with any purge right (issues/ending-verdict-reads-dropped-grants.md). A fall reopens what the ending dropped and judges again what waited on the thing.
- An expiry needs nothing: every copy of the creation carries its T in the header.
- Purge is per part: ending one thing leaves the other things in that commit alone.
- Disputes: a side that judges the purge invalid keeps the thing, and hosts keep it while the fork lasts (notes/disputes-plan.md).

**Dependents (Tess: B, authority that passed through an ended actor stands as its frozen history says).** Records are identity, `created.0` is existence: a record proves itself by its hash and needs no authority (spec/permissions.md §1), so it is not data of the thing. What judging a thing x needs of an actor t on any of x's authority paths (first admin or granted: the first admin is history, spec/permissions.md §1) is t's record and t's `roles.0` history, and it travels with x. Built (`retention/end.rs`, `labeling/certs.rs` `Certs`, `Engine::ended_upstream`, node-sync `place_records`):
- **Raw records travel.** Chain certificates carry creation records raw, in record blobs (`["records", [creation+]]`, spec/wire.md §3), never copies of the commit that minted them, which go with its retention; inbox payloads carry them in position 3. A node places the records its chains need that no entry under the label holds, as one record blob; any node's opened record blob counts once present at every host. Record blobs have no commitments: only the label-wide delete key removes one, and inbox clearing keeps them. A cross-published `created.0` stays a copy: it is the thing's own existence, which goes when it ends.
- **Frozen history travels with its dependents.** For each ended actor on an authority path into a label's closure (named first admin or holder on a live closure thing, or on such an ended actor: `Engine::ended_upstream`, a walk of the held holders), the label carries its record chain and every held edge write on it with their write certificates, placed by the dependents' holders: as closure bodies while the group still lists the ended thing (holders that keep its edges upload them again), else as certificate copies. The ending deletes the ended thing's bodies where it keeps nothing; a node that kept nothing takes a body or copy again when it opens one (`takes_late`: a part dropped by the ending counts as never received) and so deletes it no more.
- **A thing is known by its record.** A part on a thing whose record is held (from a creation or a record blob) and that is not ended is judged, and the thing reads (`Core::exists`; an invitee reads a group's `label.0` before its creation); an ended thing is unknown but for what judges its ending. A node writes to a thing only while it holds a creation of it (`Core::writable`): one that learned the record raw cannot tell the thing ended, and every node that saw the ending would ignore the write. A key actor takes writes by its record (its creation carries nothing else, and only its own nodes see it end).
- **An ending keeps** the record, the value-less creation and the `roles.0` parts while it ended by purge (for good) or a dependent is held: another thing it is on an authority path of (a held record naming it first admin, a held edge write naming it holder: `Held::named_on`), or, for a key actor, a commit it signed or acted in with a part held on another thing. Otherwise it keeps nothing, and the ended actors named on it, left with no dependent, go too (a walk up its holders). The keep is per node, but nothing observable depends on it: a node without a dependent judges nothing through the actor, and a dependent arriving brings what judges it.
- **A key actor ends** like anything, by itself (admin on itself): an account ending itself leaves its D, profile and chats; what it signed still verifies, since its record stays wherever something it signed or is on a path of is held.
- Open: a newcomer cannot read a dependent whose secrets are boxed to an ended actor holding secrets of its own: nobody boxes the ended actor's secrets once it ended (issues/ended-actor-secrets-unreachable.md).
- Open: a node that opened a history copy and the actor's record blob before its own ending, holding no dependent yet, forgets both at the ending and deletes the copy; its placer does not place a copy that went again, and the record blob is not read again (issues/ended-history-opened-before-dependent.md).
- Limits: a key actor's dependent check walks the commits (a key actor's ending is rare). Only a dependent thing's own ending re-checks the ended actors named on it: one kept for a dependent that goes any other way (access lost, `retention/forget.rs`; for a key actor, its signed part expiring, purged or ending with its thing) stays, one record and its edges per such thing. A node that holds a raw record of a thing but never its creation never sees it end: it holds no data of it and writes none to it. Paths through a live actor outside the closure are not carried for the label's own writes (as before the ending), so neither are ended actors reached only through one.
- Rejected: cutting authority through an ended thing at its ending (A: paths through it stop counting, past writes judged with its history): the same history must travel for the past writes, and everything reached through it (a group's items under an ended first admin) would lose its readers and admins at once, against "things it created live on".

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
- Deletion, new: "Purging or expiring a thing's creation ends the thing: every node drops it and ignores later writes to it."
- Dependents (Tess decided B; wording pending her sign-off): "Things it created live on: what others also run keeps running, and what an ended account wrote still shows as its own." spec/requirements.md says "Things it created live on."

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
7. **Ordinary `created.0` retention and ending.** Built: `retention/end.rs`, `Write::end`.
   - Tests: the thing is gone at every node at T or at the purge, in any order; a write after the end is ignored; a non-admin purge falls; hosts drop the ended thing's blobs.
8. **Dependents** (Tess: B, frozen history travels as chain certificates). Built: record blobs, inbox records, an ending's keep rule for every actor on an authority path and its walk up the holders, ended actors' history placed under their dependents' labels, key actors end.
   - Tests: an account ending itself leaves its group running and a node granted later verifies its writes from the label's record blob (`ending::an_ended_account_leaves_what_it_created_running_spec_commits_5`); an ended first admin or holder stays until what names it ends, then neither leaves a record (`ending::an_ended_first_admin_stays_a_chain_proof_until_its_last_dependent_goes_spec_commits_5`, `ending::an_ended_holder_stays_until_what_names_it_goes_spec_commits_5`); a node that held no dependent at the ending judges one arriving later as the others do, for a first admin and a granted admin, and so does a node granted afterwards (`ending::an_ended_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5`, `ending::authority_through_an_ended_granted_admin_stands_spec_commits_5`).

**Positions at expiry and purge (Tess).** Expiry and purge keep an item's bare position, so live items placed after it stay put (unlike an invalid write, which leaves nothing). If keeping positions turns messy for complexly edited text or lists, weak expiry and purge support there is acceptable: prefer the simple rule over a carve-out.
