# Commits
> Summary: What a commit is and how a node verifies, applies, retains and purges it.

## 1. Header
Encoding: spec/wire.md §4. Fields:
- Format version (spec/versioning.md §1).
- Author node tid and the actor tid it acts for (checked: spec/permissions.md §5.2).
- Kind: content or role (§2); compaction-snapshot marker; roster-snapshot marker (role only).
- `ts` (spec/crdt.md §2.2) and the dot form, commit or session (§3).
- Optional `expires` (§6), the expiry of every delta of the commit.
- Aspect list: per touched `(tid, ak)`: counter range `[lo, hi)`, retention (§5) and the delta hashes of its deltas. A content commit has one delta per aspect; a role commit may have several (§2), all sharing the aspect's range.
- Chunk list: the chunk, tree-node and page blobs the deltas introduce, each with the indices of the delete keys of the delta that created it (spec/crypto.md §7).
- Optional purge request (§5), optional `undoes: commit ID` (§7).
- A 16-byte random blind and the delete keys with their levels (spec/crypto.md §7); per aspect, the indices of the keys its deltas call for.
- Demotions only: the frontier (spec/permissions.md §5), inline or as a link to a chunk tree when it exceeds `CHUNK_THRESHOLD` (spec/data-model.md §6).
- Optional ephemeral marker: an ephemeral commit or a relay-only one (§2).
- The aspect, chunk, purge and delete-key lists are each inline, or a link to a chunk tree of the list's canonical bytes when it exceeds `CHUNK_THRESHOLD`; those blobs carry the commit's level-2 commitment (spec/wire.md §5) and go under every label the commit's blob goes under (spec/sync.md §3).
- Signature (spec/crypto.md §2).

- **Commit ID** = BLAKE3 of the canonical header without the signature. The signature is over the commit ID (spec/crypto.md §2).
- **Delta** bytes: spec/crdt.md §3. **Delta hash** = `kdf("delta", dedup secret of tid, delta bytes)` (spec/crypto.md §6).
- A commit may touch things of any owners and reader sets.
- A commit's size is bounded by its one blob (spec/sync.md §3):
  - a delta pages (spec/crdt.md §8), but an ephemeral commit's deltas never page;
  - the header's lists go by link, each at most `MAX_LIST_BYTES`;
  - the whole commit, its paged deltas' roots included, fits `MAX_BLOB` (spec/data-model.md §6), or the writer refuses it. Paging and chunking keep every page within a blob.

## 2. Kinds
- **Content**: deltas on aspects that are not role-class.
- **Role**: deltas only on role-class aspects (spec/data-model.md §9).
  - A role commit changes at most one `roles.0` edge, except:
    - a single-use link redemption (the grant plus L's self-removal, both on K, spec/permissions.md §8);
    - a removal of several holders' edges on one target, each gone or saying keep (spec/permissions.md §2), none of them the author's own edge or a self-removal, with one rotation: an explicit one with one frontier (revoking a link joiner together with L, spec/permissions.md §8), or a finalize of several ended edges (spec/permissions.md §2);
    - a roster snapshot (spec/permissions.md §6).
  - A removal of another holder's edge with no frontier (a finalize, spec/permissions.md §2) removes only edges past their `until` at its `ts`; an explicit removal always carries a frontier.
  - These shape rules bind the writer; a receiver does not check them and judges each edge write on its own (spec/permissions.md §5.1).
  - A grant also carries the grantee's `secrets.0` boxes; a removal or demotion carries the rotation of the target's roles it requires (spec/permissions.md §3); other rotations, re-seals and `keys.0` and `label.0` writes change no edge; all may cover many things.
  - Role commits MUST NOT carry `expires`; their retention is fixed (§5) and a purge request never names them.
  - A role commit MAY carry several deltas for one `(tid, ak)` (a roster snapshot one per edge or ledger entry, plus one per aspect carrying the reset alone): they share the aspect's counter range, their commit-level writes share the stamp `(ts, source, lo)`, and their creations use distinct counters; the aspect's delta is their join.
- **`created.0`** is carried by the thing's first durable commit, of either kind.
  - A compaction snapshot or ephemeral commit never carries it (§5). A compaction snapshot carrying `required.0^` is bad input likewise.
  - A durable commit's `created.0` part MUST be exactly one minting of the record: the delta of one write setting the thing's record (typed by the `creation` struct, spec/data-model.md §9), nothing else; otherwise that delta is bad input (§4).
  - The first content commit with a durable delta on an ephemeral thing (spec/data-model.md §1) also carries `created.0` of each ephemeral thing on that thing's owner chain and the durable adds of its ephemeral placements (spec/data-model.md §8).
- **Compaction snapshot**: content or role kind with the compaction-snapshot marker; snapshot deltas (spec/crdt.md §8); no own writes, empty counter ranges (spec/sync.md §7).
  - Written by a node that may write the aspect (admin for `keys.0` and `secrets.0`, spec/permissions.md §5.2). A receiver judges this as for any delta of its author, and a snapshot failing it gives nothing (spec/permissions.md §5.2).
  - `roles.0` and `tenures.0` are never compaction-snapshotted: a roster snapshot resets and rewrites them under its own stamps (spec/permissions.md §6).
- **Ephemeral commit**: a commit with the ephemeral marker, carrying writes of ephemeral (`~`) aspects (spec/data-model.md §2), `placed.0~` among them, one of:
  - a session-form content commit (its author's own writes under one of its sessions, §3);
  - a commit-form content compaction snapshot of one `~` aspect (an ephemeral snapshot, below).

  With the relay marker instead it is **relay-only**: writes of signal (`*`) aspects, commit form, snapshot deltas with empty tables. For an ephemeral commit of either form and any marker:
  - **Creation records**: it carries no `created.0` delta. Beside each delta a part carries the creation records (spec/wire.md §3, §4) of the ephemeral things (at its author) the delta is on or its `placed.0~` writes place that have the delta's thing's reader actor (spec/sync.md §3; a record gives its thing's dedup secret, so none goes to another reader), and of their ephemeral owner chains. A record needs no signature (it hashes to its tid). A receiver keeps those of things it does not hold as it keeps the commit (in memory).
  - **Shape**: every delta has retention `writer` with no bounds. It has no chunks, pages (each delta must fit a blob alone, spec/crdt.md §8), purge, undo or list by link. A relay-only commit carries no `expires`.
  - **Holding**: nodes and hosts hold ephemeral commits in memory only (spec/sync.md §4, §9). Nothing of them joins durable state.
  - **Receiving**: a receiver verifies, judges and applies it as the durable commit of its kind (§4, spec/permissions.md §5.2):
    - a session-form one as a content commit, with pending, atomic apply and un-merge;
    - a snapshot one as a compaction snapshot, covering held bodies (§5, spec/sync.md §9);
    - a relay-only one is delivered and never held (spec/sync.md §9).
- An **ephemeral snapshot** is a compaction snapshot like any (spec/crdt.md §8, §5).
  - Its delta is the writer's state of the aspect, every author's writes under their stamps, with the tables over the sessions that occur in it, but without the deltas of commits that have an `expires` (they vanish whole at their time, spec/crdt.md §4.7: none is carried, counted or covered).
  - A writer MAY instead snapshot the join of some of its own session-form bodies alone (coalescing, spec/sync.md §9), with its own session's entry reaching the last of their counters.
- **Storage class**: an aspect's storage class is its AK's lifetime marker (spec/data-model.md §2), alike at every node. A part is bad when it is on:
  - an AK without `~` in an ephemeral commit that is not relay-only;
  - an AK without `*` in a relay-only commit;
  - an AK with `~` or `*` in a durable commit.

  For such a part: a writer MUST NOT write one (a durable write on an ephemeral thing is a durable commit persisting it, spec/data-model.md §1), and a receiver drops it alone, as a part not matching its header entry (§4).
- A commit spanning several kinds is invalid.

## 3. Dot forms
- **Commit form**: dots `(commit ID, index)`, unlinkable across commits. Any content commit but an ephemeral one may use it.
  - A key actor whose key is used from more than one device (link key, recovery key) MUST use it, and every role commit (roster snapshots included) and every compaction snapshot MUST use it.
- **Session form**: dots `(Session(author node, nonce), counter)` (spec/crdt.md §2.1), counters per (aspect, session), contiguous from 1; the header carries the 16-byte nonce.
  - Content commits (§2) with own writes otherwise use it, durable and ephemeral alike; an ephemeral content commit MUST use it.
  - Session form on any other kind (§2: role, compaction snapshot) is bad input.

## 4. Verification and application
- A commit's signature MUST verify; receivers dedup by commit ID.
- Each **delta** is judged on its own, by its author's authority on that delta's thing (spec/permissions.md §5); an invalid delta is un-merged alone (spec/crdt.md §4.6), the commit's other deltas stand.
- A node **syncs** what it was asked to and what the `group.0` values it holds put in those groups' closures (spec/sync.md §3), judged as of each examination.
- A commit is **pending**, not applied and counted as not received, while any of these holds:
  - it is parked (spec/versioning.md §2);
  - the author's `created.0` record is unknown;
  - its `ts` is more than `MAX_DRIFT` ahead (spec/crdt.md §2.2);
  - a header list or frontier given by link (spec/wire.md §4) is not resolved;
  - atomic apply waits;
  - a part waits and holds it (below);
  - every part of it the node holds waits;
  - the node holds no part of it, and a thing of it waits or a delta of it is missing and not counted as held (synced or not). A permanent delta (§5) of it or an item of its purge request on a thing the node syncs counts here as a held part, so its other things and deltas gate it as those of a commit with a held part do.

  A part past its expiry decides none of this: a commit that would wait without it waits, and the part goes (§5). A content commit with no part held and every delta counted held applies as its header alone, and counts as a commit on each aspect its header lists.
- A **thing waits** while any of these holds:
  - its `created.0` record is unknown;
  - a `created.0` record on its owner chain is unknown;
  - the author is not on that chain and no owner link, ownerless thing's first admin (its record, spec/permissions.md §1) or holder named by an applied part's edge write, roster or ledger tenure, whether the walk applies it or not, leads from the author to it.
- A held **part waits** while any of these holds:
  - its thing waits;
  - a page of it is not held (spec/crdt.md §8);
  - it is a roster snapshot's `tenures.0` delta linking a frontier whose blobs are not held (spec/permissions.md §6);
  - it is parked (spec/versioning.md §2).
- **What a wait holds**:
  - The wait of a thing the node syncs, or of a part on one, holds the whole commit, whether a part on that thing is held or not.
  - Except the wait of a part that atomic apply counts as held when missing (below), and that of a linked frontier: they hold nothing back.
  - Any other part waits alone, as does every part of a role commit (not a snapshot) once the node holds any delta of it and every late part of an applied commit. The commit's other parts apply, its waiting parts count as not received and each joins when its wait ends.
- A **thing's content** is its parts on aspects neither role-class nor `created.0` (of a commit other than an ephemeral snapshot). Once a part of it is held, the thing's content applies whole or not at all, synced or not: a waiting part or a delta missing, neither counted as held (below), holds the rest of it.
- A held `created.0` part never waits for the commit's other parts: it applies when its thing does not wait, and the commit still waits whole, or its parts alone, as if nothing of it had applied.
- **Order independence**: which parts apply is a function of the parts and other data held and of what the node was asked to sync, never of arrival order or of which parts came together. One exception, which lasts while a part stays away: parts that applied before a thing of the commit entered what the node syncs stay applied, on things other than that one and, of a role-class snapshot, on that thing too.
- A thing's **possible admins**, by the role commits the node has applied (a pending one, parked included, gives nothing), of any validity and whatever followed: the least set holding the thing and, with each member, its owner or first admin and any holder named with admin on that member by an edge write, roster or ledger entry a member signed.
- A thing's **possible writers**, by the same data: the least set holding the possible admins of the thing and of each member, and any holder named with write or above on the thing or on a member by one of that thing's or that member's possible admins.
- **Atomic apply**: a node applies a commit only once it holds every delta of it on a thing it syncs (above), with the pages of every paged delta (spec/crdt.md §8). Chunk blobs of large atomic values (spec/data-model.md §6) are not waited for. It then joins all those deltas in one storage transaction and fires listeners after. Pending commits are re-examined when a thing enters or leaves what the node syncs. A delta counts as held when any of these holds:
  - **Dropped or expired**: it was dropped (spec/crdt.md §8) or expired.
  - **Purged**: an applied purge request stamped after it names it, and each of the request's author and actor could hold the right of the delta's purgeable-by by any role any held write ever gave, whatever that role's validity:
    - for `admin`, a possible admin of the thing;
    - for `writer`, a possible writer of the thing;
    - for `author`, the delta's actor or a possible writer of it, and the actor a possible writer of the thing;
    - for `author_or_admin`, either of the `admin` and `author` cases.
  - **Past keep at most**: it is under a keep at most, the node has applied another commit with a delta on the aspect (the delta held or not), of any validity, stamped no earlier than its commit, and its bound by §5 for a body with no live write has passed on the node's corrected clock, the first death taken at the earliest such commit's `ts`, whether or not that commit supersedes a write of the delta.
    - An absolute bound passing with no such commit counts for nothing: a body with a live write leaves only with a carrier (§5).
    - This clause does not read whether the delta holds a live write, so it also applies a commit without a live delta still on its way.
    - With no such commit the commit waits, also for a delta that left with no carrier when every commit on its aspect as late has left (expired, purged) or none was (its write's superseder is stamped before it).
  - **Breaks a required retention**: it breaks an entry governing it of a held `required.0^` delta on its thing ordered before its commit, whatever that delta's validity, signed by a possible admin of the thing (§5).
  - **Under a later snapshot**: the node holds a compaction snapshot of its aspect stamped after the commit, whatever the snapshot's validity, signed by a possible writer of the thing (a possible admin where spec/permissions.md §5.2 has the snapshot need admin), while the node holds the snapshot's body or dropped it other than as covered (§5; spec/crdt.md §8).
  - **Author lowered**: the node holds one of the following on the delta's thing or a thing up its owner chain, signed by a possible admin of that thing, with a frontier that does not list the delta's commit, whatever follows them and whatever their order against the delta's commit:
    - a role commit with a frontier, of any validity, by another actor, whose edge write on that thing removes the edge of the delta's author or its header's actor or sets it below the role the delta needs;
    - a roster snapshot's ledger entry, in a snapshot whose held parts show at least one roster edge, with a frontier, of the delta's author or its header's actor with that role or above, that no roster edge or later-ending entry of that role or above in the snapshot starts at the end of.
  - **Role commit**: it is a delta of a role commit (not a snapshot) and the node holds any delta of that commit (it may hold only a copy of some parts: a certificate copy or an inbox blob, spec/sync.md §3). The commit applies without the missing ones and each joins if it arrives later.
  - **Wrong storage class**: it is on a key of another storage class than its commit's (§2).
- A delta of an already applied commit that arrives later (the node began syncing its label after applying, the delta counted as held, or its body counts as never received, §5) is joined on arrival, a live one past its keep at most included.
- Role commits are applied before content.
- Two commits of one session whose counter ranges on one aspect overlap are both invalid.
- **Judged alone**: a fault of the header or signature refuses the commit, in any copy. Each delta is judged by itself, from the signed header, its bytes and held data; its fault never refuses another delta:
  - Bytes that do not match the header's delta hash, or a part index naming no delta, are not that delta: dropped, and any copy matching the hash is taken as if they never came. A blob holding nothing else is bad input.
  - A part on an aspect of the wrong storage class (§2) is dropped.
  - A delta that matches and is bad by itself never applies. Only those bytes can match, so nothing marks it: it is judged again if it comes again. Bad by itself means:
    - it does not decode;
    - a `created.0` delta that is not one minting of its record;
    - a `roles.0` write inside an entry it did not create, or a value that is no well-formed edge (spec/permissions.md §2);
    - a value held unchunked that spec/data-model.md §6 chunks;
    - a carried write stamped after its commit;
    - a linked frontier that spec/permissions.md §6 calls bad input by itself.
  - While the commit is pending such a delta stays held and counts as held for atomic apply.
  - A blob holding only such deltas, of a commit that is a role commit, is applied, or has none of them on a thing the node syncs, is bad input; otherwise the commit applies without them.
  - Where such a delta's thing's content, or the commit, waits, the delta is judged when that wait ends.
- **Copies**: before a thing's `created.0` record is known the hash of a delta on it cannot be checked, and before its author's the signature.
  - A pending commit keeps the first copy of each such delta and of the signature.
  - A copy that proves not to match goes, and a node then judges again the copies of the commit it holds as blobs; this brings back no delta counting as never received (§5).
  - A copy it no longer holds comes back as a holder's new upload (spec/sync.md §6).
- A commit blob whose clear prefix disagrees with its header (expiry, the commitments to the delete keys its deltas list; spec/sync.md §1) is bad input.

## 5. Retention and purge
Every delta carries **retention** on the wire: who may purge it and how long its body is kept; its commit carries its expiry (§6). The writer fills both from the schema's defaults per AK (spec/data-model.md §2); a commit may set retention per aspect; an untyped write (no schema for the AK) defaults to `author_or_admin` with no keep bounds and no expiry. Retention is immutable: to change it, purge and write again.

### Who and how long
- **Purgeable by**: a set, not a scale: `nobody` (none), `admin` (the thing's admins), `author` (the delta's author), `author_or_admin` (both), `writer` (every writer, so both too).
  - A `nobody` delta shares a commit only with `nobody` deltas, `created.0` and `required.0^` aside, which go with any; a writer splits a write mixing them into commits (§6).
  - No exception widens it: a body whose set has no holder stays until a keep-at-most bound or expiry, if any.
  - A member of the set may drop the delta's body: by purge request (spec/permissions.md §7), by compaction, and by deleting its blobs at hosts (spec/sync.md §5). Delete keys follow it (spec/crypto.md §7).
  - A **right holder** is a node that holds the right now.
- **Keep at least** and **keep at most**: each optional. Keep at least is an absolute time, a duration after the body is replaced, or both (the later counts). Keep at most is an absolute time T, **0 after replaced** (a relative bound of 0; no other duration), or both (the earlier counts); 0 after replaced exists only under `writer`. Where the two bounds disagree, keep at most wins.

### Bodies and deaths
- A **body** is a blob of a commit (spec/sync.md §3): its held deltas, each in the section of its thing's reader actor; a rewrite holds fewer. Keep bounds and deaths are read per retention class (retention and delete keys) of its deltas.
- A write **dies** when a later write supersedes it or at its delta's expiry (spec/crdt.md §4.8). A body is **replaced** as its writes die.
- Each node dates deaths for itself, per body the first and last so far:
  - a superseded write's death at the `ts` of the first superseder the node held, so never earlier than its death (spec/crdt.md §4.8); a superseder held later with a lower `ts` moves no date;
  - a validity flip, an un-merge or a new judgment of an invalid delta may date the aspect's deaths again from what it then holds;
  - an expiry dates none: the delta's body goes at T (§6) and a snapshot holds the write value-less.
- A write of a delta invalid here does not die, nor does a valid write an un-merge took with nothing superseding it (spec/crdt.md §4.6), nor, for an invalid snapshot's body, any write it carries. But under keep at most 0 after replaced, on a commit other than a role commit, each counts dead from its **fall** for its body's dates. With no such bound the body stays.
  - An invalid delta's fall is at the `ts` of the demotion that its judgment names (spec/permissions.md §5.2), no earlier than its own `ts`, and with none at its own `ts`.
  - An un-merged write's fall is at the latest fall among the invalid deltas of applied commits on the aspect, no earlier than its own `ts`.
  - Only an applied commit's judgment counts: a commit that waits (§4) has no fall.
- Nodes holding the same commits may hold different dates and different bodies. A write arriving after every write superseding it went with a body dropped for its keep bounds, none of them live, has no death there, and its body stays until a later death or another drop.

### Covered
- A body is **covered** by a valid snapshot the node holds (spec/permissions.md §5.2) when joining each of its deltas into the snapshot's fragment of that aspect leaves its canonical bytes unchanged (spec/crdt.md §3.3): every live write of the body is in the snapshot, and canonical form carries no dead content. A held body is judged by this join whatever the snapshot's tables say.
  - A snapshot body is covered only if it is stamped no later than the covering snapshot.
  - Every write the covering snapshot holds under a dot the body holds a write of (or, for a body that is not a snapshot, under one of its own dots: its counter range, its commit ID) MUST be the body's write at the same position with the same `ts` and value, or a value-less copy of it (the join then decides: a value-less copy of a valued write leaves the body uncovered); a valid snapshot body's copies all count (spec/permissions.md §5.2); an invalid one's copies of writes whose own delta the node received and judges valid are left out of the join.
  - A body the node cannot join, a snapshot whose pages the node has not fetched, or a snapshot body it has not received (a late part, or one counting as never received again, spec/permissions.md §5.2) establishes nothing: the body is neither covered nor uncovered for it (spec/sync.md §6).
  - A body holding no delta is covered (a lasting header is must-hold all the same, spec/sync.md §6), unless it is session-form and the snapshot's frontier has an entry for its session short of its counters (no entry: the snapshot holds no write of the session, spec/crdt.md §8).
  - A delta with an expiry is never covered (spec/crdt.md §8).
  - A snapshot written from a node's whole state of an aspect covers every body of it the node had applied, except those spec/crdt.md §8 never covers.

### Keep bounds
- **Keep at least**: before the bound (last death so far plus D, or T) a body leaves the labels of its things' groups only by purge request: compaction MUST NOT drop it, right holders MUST NOT delete it at hosts and a demotion's frontier does not leave it out as covered (spec/permissions.md §5.1). A body with no dead writes is past a relative bound.
- **Keep at most**: the bound is T, or under 0 after replaced the first death plus, while the body has a live write, `AT_MOST_GRACE` (never added to T); with both, the earlier.
  - A **live write** of a body is any write of its deltas the node's state holds by dot, resets and value-less writes included, and every sequence element record of its deltas the state holds, with or without a write: bare anchors (dead per spec/crdt.md §4.8, kept per spec/crdt.md §5.7) and an invalid delta's hidden anchors (spec/crdt.md §4.6) alike. An element's or entry's tombstone is not one of its creator's (it holds the remover's reset, not the creation).
  - Each node judges liveness on its own state and dates on its own deaths, so bounds may differ between nodes holding the same commits. A right holder uploads the killing commit before any delete in the same pass.
  - A node drops a body no earlier than its bound from those dates. By the bound every node MUST drop the body, and a node whose dates put the bound in the past when it learns them (a death learned late) drops it then; its live writes stay in the node's state (spec/crdt.md §4.6); right holders delete it at hosts when next online after the bound.
  - A node judges an absolute bound from the header (T, or the purge floor below) and its corrected clock alone, deaths aside, and drops a body applied at or past it only after its apply, so that a carrier can go first (below). A held part of a waiting commit keeps its body until its commit applies.
  - **Carrier**: a node that may write the aspect and holds no snapshot covering a body with live writes writes one before dropping the body (it is held and uploaded like any must-hold body). A body with live writes is deleted at a label only while another entry under it carries them (spec/sync.md §7).
  - A body with no live write needs no carrier: under 0 after replaced, the node applying the kill that leaves it none drops it in that transaction and deletes it at hosts in the same sync.
- **Never received**: a body dropped for its keep bounds (at its bound or as its writes died) counts as never received from then on, as a missing delta counted as held does (§4).
  - Its live writes stay in the state.
  - The node does not fetch it on its own, but for a part dropped while invalid that turns valid: it is missing again and fetched, and until it arrives the node may read less, the aspect suspect.
  - A copy that arrives again joins as a late part and is judged again (dropped at once past its bound or purged; held when a write that killed it, or one of its own, has turned invalid or valid).
  - Its holders upload it while it is must-hold (spec/sync.md §6), so nodes holding the same bodies read alike.
- **A waiting part past its expiry**: a part that waits (§4) when its expiry passes goes from the node at T, and one arriving past T goes if it waits or its commit would wait without it. Either counts as never received: its non-value writes join only through snapshots. Every local copy goes with it. That node may read what came before the part until a writer next compacts (spec/sync.md §7); a commit such a part applied before T stays applied.
- **A waiting part under a purge**: a waiting part that an applied purge request names whose author may purge it (judged once the node holds the request and the commit's header) is held value-less from then on.
  - The node keeps it as its leftover (spec/crdt.md §4.7) and no other local copy of it; it waits and applies as that, so nodes holding the same commits read alike.
  - With a page of it not held it cannot be stripped: it goes at once with every local copy, as a part missing when purged.
  - If the request no longer drops it when its commit applies, it is fetched again like any missing delta.
  - While its thing's record is unknown no right can be judged, so such a part keeps its values in the pending copy, for good if the record never comes; a request on that thing waits with it.
  - A snapshot part has no values of its own: it waits whole and drops once applied.
- For any dropped delta (here or below), a received blob holding it that may also hold the only true copy of a waiting part of the same commit (one whose slot a copy not yet checkable holds, §4 Copies) is kept until that copy is judged.
- Where such a drop may leave a node reading less than one that kept the data, it reports the aspect suspect (spec/permissions.md §4).
- **Between the bounds** a right holder may drop a covered body (compaction, spec/sync.md §7) when the covering snapshot's own commit holds the right over it, as a purge request would at that snapshot's key (spec/permissions.md §7), and the node itself holds it now. A snapshot without the right carries the body's live writes and covers it for must-hold (spec/sync.md §6) but drops nothing, at any node. `nobody` makes that window empty. Snapshot bodies follow the same rules.
- **Carrier only**: a compaction snapshot whose retention (on the wire) has a keep at least (an absolute bound, or a relative one above 0) and a keep at most (either component).
  - It is valid and its writes join, and it carries the live writes of bodies dropped at their keep-at-most bounds (above, spec/sync.md §7), but no body is dropped as covered by it and it covers none for must-hold (spec/sync.md §6).
  - Each node judges this from the snapshot's retention alone, so alike; a delta's retention is immutable, so a later schema or default change re-judges nothing.
  - Compaction skips an aspect whose snapshot would be a carrier only; a node writes one only as the carrier of a body with live writes it must drop (keep at most, purge).
  - Inside one body the cut stays: under such retention a body's keep at most counts from its first death, so a write of it dying later keeps less than its keep at least (keep at most wins).

### Required retention
- **Required retention**: `required.0^` (spec/data-model.md §9) has, in `rules`, AK prefixes mapped to a purgeable-by, keep bounds and an optional expiry duration, and, in `keep`, the default for removals (spec/permissions.md §2), read in force as the rules are.
  - A delta answers to it unless it is a compaction snapshot's or its aspect has fixed retention or is not durable.
  - The setting **in force** at a key is what the newest valid `required.0^` delta on the thing ordered before that key says (spec/permissions.md §5.2); none: nothing is required.
  - The entry governing an AK is the one with its longest prefix, the empty prefix matching every AK; no entry: nothing is required.
  - A delta **breaks** an entry that governs it if it does not carry exactly the entry's purgeable-by and bounds and its commit, with a duration, `expires` = `wall_ms(ts)` + that duration, without one no `expires`.
  - A delta that breaks the setting in force at its key is invalid; its commit's other deltas are judged on their own.
  - Each `required.0^` delta is read alone: its value is the whole setting, and a delta not reading as the aspect's type, with more than `MAX_REQUIRED_ENTRIES` entries or with a prefix longer than `MAX_AK_BYTES`, requires nothing.
  - A writer fills the required retention and expiry and refuses others, writes `required.0^` whole (never by path, within those bounds, with no entry a write could not meet) and does not undo it.
  - A change judges only later keys; it rewrites no delta's retention.

### Purge
- **Purge request**: a header field naming earlier deltas (of commits with a smaller `ts`; a later one is not named) by commit, by a whole aspect history (its compaction snapshots included), or by author on an aspect (spec/wire.md §4). A named snapshot's right is judged by its own retention and header. It MUST NOT name role-class deltas.
  - A later-arriving delta an applied request names falls under it as one held does.
  - Every node applying it drops, at any time, the named deltas its author may purge (spec/permissions.md §7): from then on it holds their value-carrying writes value-less (spec/crdt.md §4.7) and holds each named delta's own body and every body carrying their values as its leftover (spec/crdt.md §4.7 Copies: snapshots, and deltas carrying a copy under the named delta's dots, an undelete's char or an entry's key a later write repeats), whatever the order the request, the named delta's commit and the carrying body arrive in. A snapshot a request names itself has no values of its own: its body is dropped, and comes back with a fall. A node judges a named delta once it holds the request and that commit's header (which the right and the writes it names depend on).
  - A writer that, after applying it, holds no covering snapshot of the aspect under a label it writes re-snapshots there (duplicates are harmless, spec/sync.md §7).
  - A request SHOULD name dead writes; the writer resets live content in the same commit.
  - A commit carrying a request has a delta (it is what places the commit under the thing's labels): where no reset is wanted, a write of `purge.0` (spec/data-model.md §9).
  - A commit carrying a purge request MUST NOT carry `expires`; its blobs are kept at least until `wall_ms(ts) + ROLE_KEEP`, whatever its deltas' keep bounds (at least and at most).
- **Purging drops bodies, never headers**: a node keeps the header of every durable commit it applied.
  - An ephemeral commit goes whole, header included, once none of its deltas is held and none waits: covered, expired or superseded (spec/sync.md §9). A copy arriving again applies again and goes again by the same rules.
  - A node dropping a body for a purge keeps the commit as a blob without the purged deltas: same header and commit ID, new blob, held and uploaded like any body. With none left it holds only the header.
  - A **header-only blob** goes under a label only as a lasting header (below); its prefix has no expiry and no commitments.
- A delta is **permanent** when it is durable, its aspect has no fixed retention, its retention has keep at least `abs` forever and no keep at most, and its commit has no `expires`. Only a purge request removes its body.
- A commit is **lasting** on thing t when either:
  - a permanent delta of it on t is dropped (other than for breaking a required retention, spec/permissions.md §7);
  - its purge request has dropped a permanent delta on t at this node (spec/permissions.md §7: its author held the right, as the node then judged; a request that falls stays lasting there).

  A device coming later, with no snapshot of the aspect stamped after its commit, counts a purged delta as held only by an applied request (§4). A lasting commit's header is never forgotten, and every label of a group with t in its closure, whose actor may read t, holds a blob of the commit for good (spec/sync.md §6): a body of it, else a header-only blob. A purge of any other delta leaves nothing at a label. The commit reads as a held commit without that delta's body: its author, actor, `ts` and retention stay, and whether to show it is the reader's choice.
- **Dropping a body** means destroying every local copy (undo buffers and pre-reset snapshots included), its delta nonce and every local index entry derived from it. Holding one as its leftover destroys every copy of its values the same way; the leftover is a local body (never uploaded, deleted at hosts as a dropped one).
  - What the part was judged stays: its validity, the role its writes needed, and for a `secrets.0` or `keys.0` delta the epochs it boxed or keyed, whose introducing commit spec/crypto.md §4 asks for, and the sealed names of its boxes to the holders its edge writes put, a grant's.
  - A leftover holding no value of its own writes (expired, purged) is never dropped, for keep bounds or as covered; it goes only with its thing (spec/permissions.md §3) or for a copy of its body that holds values again (a fallen purge). A body held as its leftover only for the copies it carries is a body like a whole one for keep bounds, deaths and covering.
  - Exception: a compaction snapshot's part dropped other than as covered (for its keep bounds) still counts for atomic apply (§4) and suspect flags (spec/permissions.md §4) from its header alone; a part dropped as covered need not (its coverer is valid and stamped no earlier). One held as its leftover is held.
- A dropped body cannot be undone (§7); under at most 0 others' resets beat undo.

### Fixed retention
- **Fixed retention**:
  - role-class deltas: `admin`, keep at least `ROLE_KEEP` after replaced (a roster snapshot replaces `roles.0` and `tenures.0` deltas, compaction snapshots or later writes the other role-class aspects, spec/permissions.md §6);
  - `created.0` and `required.0^`: `nobody`, kept forever (`abs` forever); they are never snapshotted (§2);
  - `purge.0`: `author_or_admin` with no keep bounds, its snapshots too;
  - a certificate copy carries its commit's;
  - snapshots of role-class aspects keep it.
- Other compaction-snapshot deltas are `writer` (a receiver checks this; the bounds below are the writer's, from what it holds), with bounds from the **own deltas** of the writes the snapshot carries live (live as for keep at most):
  - keep at least: the longest relative bound among them, with no absolute one;
  - keep at most: the strictest per component, 0 after replaced if any of them has it and the earliest absolute bound later than the snapshot's `wall_ms(ts)`, an absolute bound at or before it counting as 0 after replaced.
- A write's own deltas are its own commits' deltas on the aspect (spec/permissions.md §5.2). For writes whose own commit's header the node does not hold, every held snapshot body of the aspect carrying one of them stands in, and if some such write no held snapshot body carries, every compaction snapshot of the aspect the node applied.
- No schema enters the bounds; a snapshot names the schema of the last applied delta of the aspect in `(ts, ID)` order that names one, else none.

## 6. Expiry
- `expires: T` (wall ms, `T > wall_ms(ts)`, else invalid), one per commit: every delta of it expires at T. A commit carrying a fixed-retention aspect (§5) carries none.
- A writer whose `ts` has reached the T it was given (its HLC ahead of its clock) writes `wall_ms(ts) + 1`.
- The schema may give a default per AK as a duration from the write.
- The blob prefix carries the commit's T (spec/sync.md §1, §3).
- A writer splits a write whose deltas want different expiries, or that mixes `nobody` deltas with others (§5), into commits, one per expiry and class, under one `ts` (spec/crdt.md §2.2), the one carrying the things' records first. `required.0^` goes in the commit holding its thing's other deltas of the write.
- At T every value-carrying write of the delta dies (spec/crdt.md §4.7): every node holds them value-less, the body and every held body carrying a copy of their values as its leftover, whatever the delta's keep-at-least bound.
- A delta never received stays never received: a copy arriving after T joins value-less (held as its leftover from then on), and what a held snapshot gave under its dots goes with the snapshot (spec/permissions.md §5.2).
- Hosts delete the blob at T unattended (spec/sync.md §5).

## 7. Undo
- An undo commit (a revert) sets `undoes` to the undone commit's ID; its deltas are chosen per spec/crdt.md §4.6 (undoing a creation deletes the thing, so they may touch aspects the undone commit did not). A commit whose body was dropped cannot be undone. Redo is an undo of the undo commit. Undoing ephemeral writes (spec/data-model.md §2) writes ephemeral writes chosen the same way, from the writing node's in-memory record of them; no commit names them.
