# Commits
> Summary: What a commit is and how a node verifies, applies, retains and purges it.

## 1. Header
Encoding: spec/wire.md §4. Fields:
- Format version (spec/versioning.md §1).
- Author tid (an account, or a key actor signing as itself), the epoch an account signs at, and the actor tid it acts for (checked: spec/permissions.md §5.2, §5.5); a rotation (spec/crypto.md §9).
- Kind: content or role (§2); compaction-snapshot marker.
- `ts` (spec/crdt.md §2.2) and the dot form, commit or session (§3).
- Optional `expires` (§6), the expiry of every delta of the commit.
- Aspect list: per touched `(tid, ak)`: counter range `[lo, hi)`, retention (§5), the delta hash of its one delta, and for a durable signal's delta optionally the fire it `replaces` (§5 Signals).
- Chunk list: the chunk, tree-node and page blobs the deltas introduce, each with the indices of the delete keys of the delta that created it (spec/crypto.md §7).
- Optional purge request (§5), optional `undoes: commit ID` (§7).
- A 16-byte random blind and the delete keys with their levels (spec/crypto.md §7); per aspect, the indices of the keys its deltas call for.
- Explicit removals and edge writes that audit only: the frontier (spec/permissions.md §5.1 step 4), inline or as a link to a chunk tree when it exceeds `CHUNK_THRESHOLD` (spec/data-model.md §6).
- Optional ephemeral marker: an ephemeral commit or a relay-only one (§2).
- The aspect, chunk, purge and delete-key lists are each inline, or a link to a chunk tree of the list's canonical bytes when it exceeds `CHUNK_THRESHOLD`; those blobs carry the commit's level-2 commitment (spec/wire.md §5) and go under every label the commit's blob goes under (spec/sync.md §3).
- Signature (spec/crypto.md §2).

- **Commit ID** = BLAKE3 of the canonical header without the signature. The signature is over the commit ID (spec/crypto.md §2).
- **Delta** bytes: spec/crdt.md §3. **Delta hash** = `kdf("delta", dedup secret of tid, delta bytes)` (spec/crypto.md §6).
- A commit may touch any things, of any reader sets.
- A commit's size is bounded by its one blob (spec/sync.md §3):
  - a delta pages (spec/crdt.md §8), but an ephemeral commit's deltas never page;
  - the header's lists go by link, each at most `MAX_LIST_BYTES`;
  - the whole commit, its paged deltas' roots included, fits `MAX_BLOB` (spec/data-model.md §6), or the writer refuses it. Paging and chunking keep every page within a blob.

## 2. Kinds
- **Content**: deltas on aspects that are not role-class.
- **Role**: deltas only on role-class aspects (spec/data-model.md §9).
  - A role commit changes at most one `roles.0` grant, except:
    - a single-use link redemption (the grant plus L's self-removal, both on K, spec/permissions.md §7);
    - a removal of several holders' grants on one target, each gone or saying retain (spec/permissions.md §2), none of them the author's own grant or a self-removal, with one rotation: an explicit one with one frontier (revoking a link joiner together with L, spec/permissions.md §7), or a finalize of several ended grants (spec/permissions.md §2).
  - A removal of another holder's grant with no frontier (a finalize, spec/permissions.md §2) removes only grants past their `until` at its `ts`; an explicit removal always carries a frontier.
  - These shape rules bind the writer; a receiver does not check them and judges each edge write on its own (spec/permissions.md §5.1).
  - A grant also carries the grantee's `secrets.0` boxes; a removal or demotion carries the rotation of the target's roles it requires, except while Seal waits (spec/permissions.md §3); other rotations, re-seals and `keys.0` and `label.0` writes change no grant; all may cover many things.
  - Role commits MUST NOT carry `expires`; their retention is fixed (§5) and a purge request never names them.
- **`created.0`** is carried by the thing's first durable commit, of either kind; a commit whose only deltas are `created.0` and that does not expire is a role commit.
  - A compaction snapshot or ephemeral commit never carries it (§5). A compaction snapshot carrying `required^.0` is bad input likewise.
  - A durable commit's `created.0` part MUST be exactly one minting of the record: the delta of one write setting the thing's record (typed by the `creation` struct, spec/data-model.md §9), nothing else; otherwise that delta is bad input (§4).
- **Compaction snapshot**: content or role kind with the compaction-snapshot marker; snapshot deltas (spec/crdt.md §8); no own writes, empty counter ranges (spec/sync.md §7).
  - Written by a node that may write the aspect (admin for `keys.0` and `secrets.0`, spec/permissions.md §5.2). A receiver judges this as for any delta of its author, and a snapshot failing it gives nothing (spec/permissions.md §5.2).
  - `roles.0` is never compaction-snapshotted: the role timeline walks every edge write (spec/permissions.md §5.1).
- **Ephemeral commit**: a commit with the ephemeral marker, carrying writes of ephemeral (`+`) aspects (spec/data-model.md §2), one of:
  - a content commit (its author's own writes, in its form, §3);
  - a content compaction snapshot of one `+` aspect (an ephemeral snapshot, below).

  With the relay marker instead it is **relay-only**: writes of ephemeral signal (`+~`) aspects, commit form, snapshot deltas with empty tables. For an ephemeral commit of either form and any marker:
  - **Records**: it carries no creation record; its things' records come in durable commits, and a part on a thing whose record is not held waits for it (§4).
  - **Shape**: every delta has retention `writer`, with no history given or keep history (§5); a relay-only commit's has none given. It has no chunks, pages (each delta must fit a blob alone, spec/crdt.md §8), purge or list by link. A relay-only commit carries no `expires` and no `undoes`.
  - **Holding**: nodes and hosts hold ephemeral commits in memory only (spec/sync.md §4, §9). Nothing of them joins durable state.
  - **Receiving**: a receiver verifies, judges and applies it as the durable commit of its kind (§4, spec/permissions.md §5.2):
    - a content commit as one, with pending, apply and un-merge;
    - a snapshot one as a compaction snapshot, covering held bodies (§5, spec/sync.md §9);
    - a relay-only one is delivered and never held (spec/sync.md §9).
- An **ephemeral snapshot** is a compaction snapshot like any (spec/crdt.md §8, §5).
  - Its delta is the writer's state of the aspect, every author's writes under their stamps, with the tables over the sources that occur in it, the values of deltas with an `expires` value-less (spec/crdt.md §8: none is covered).
  - A writer MAY instead snapshot the join of some of its own session-form bodies alone (coalescing, spec/sync.md §9), with its own session's entry reaching the last of their counters.
- **Storage class**: an aspect's storage class is given by its AK's markers (spec/data-model.md §2), alike at every node. A part is bad when it is on:
  - an AK that is not an ephemeral aspect (`+` and `.`) in an ephemeral commit that is not relay-only;
  - an AK that is not an ephemeral signal (`+` and `~`) in a relay-only commit;
  - an AK with `+` in a durable commit;
  - a signal AK in a compaction snapshot, or with a retention whose history is not keep history (§5 Signals);
  - an AK other than a durable signal (`~` without `+`), or a commit with an ephemeral marker, with `replaces` (§5 Signals).

  For such a part: a writer MUST NOT write one, and a receiver drops it alone, as a part not matching its header entry (§4).
- A commit spanning several kinds is invalid.

## 3. Dot forms
- **Commit form**: dots `(commit ID, index)`, unlinkable across commits. Any content commit, durable or ephemeral, may use it.
  - A key actor other than an account whose key is used from more than one node (link key) MUST use it, and every role commit and every compaction snapshot MUST use it.
- **Session form**: dots `(Session(author, nonce), counter)` (spec/crdt.md §2.1), counters per (aspect, session), contiguous from 1; the header carries the 16-byte nonce.
  - Content commits (§2) with own writes otherwise use it, durable and ephemeral alike.
  - Session form on any other kind (§2: role, compaction snapshot) is bad input.

## 4. Verification and application
- A commit's signature MUST verify; receivers dedup by commit ID.
- Each **delta** is judged on its own, by its author's authority on that delta's thing (spec/permissions.md §5); an invalid delta is un-merged alone (spec/crdt.md §4.6), the commit's other deltas stand.
- A commit is **pending**, not applied and counted as not received, while any of these holds:
  - it is parked (spec/versioning.md §2);
  - its author is an account and the rotation minting the epoch it names is not held (spec/permissions.md §5.5);
  - its `ts` is more than `MAX_DRIFT` ahead (spec/crdt.md §2.2);
  - a header list or frontier given by link (spec/wire.md §4) is not resolved;
  - the node holds parts of it and every one waits.
- **Unjudgeable**: a node keeps no part it cannot judge and keeps what it needs to fetch what judges it.
  - A commit is unjudgeable while its author's or actor's `created.0` record is unknown; so is a held part while its thing's record or a record on its thing's chain (spec/permissions.md §1) is unknown, or the author is not on that chain and no record edge or holder named by an applied part's edge write, whether the walk applies it or not, leads from the author to it.
  - No byte of such a commit or part is kept past the pass that fetched it. A node judges one pass's fetch together: commits carrying `created.0` first, then role commits by `ts`; it discards only what is still unjudgeable at the end of the pass.
  - Before discarding, the node reads the `secrets.0` boxes of what it opened (spec/crypto.md Reading-only secrets). Nothing else of it stays but which record the blob awaits.
  - The node fetches a discarded commit or part again when what it awaits arrives; it is judged afresh and may await the next record.
  - A commit with every held part unjudgeable holds nothing and is not applied, whatever would make it pending; a commit with some other part applies, the unjudgeable part counting as never received until it is fetched again.
  - A commit that awaits and whose expiry passes counts as never received, as for a node it never reached: it flags nothing (spec/permissions.md §4 Suspect), and the entry shows nothing here until a writer compacts.
  - A commit that awaits is as if it had not arrived: a deletion decided meanwhile (a covering snapshot's author dropped by it, a body removed) stands, and the deleted body counts as never received until it is fetched again.
  - **Limits**: an insider can exhaust the reading-only budget and delay honest grants until its entries leave. A hostile writer with a k-aspect blob can cause k refetches by publishing k records one at a time.

  A commit with no part held applies as its header alone, and counts as a commit on each aspect its header lists.
- A held **part waits** while any of these holds:
  - a page of it is not held (spec/crdt.md §8);
  - it is parked (spec/versioning.md §2).
- **Apply**: a node applies in one storage transaction every part it holds that does not wait, and fires listeners after. Nothing waits for a part: a waiting part waits alone, counts as not received and joins when its wait ends, and a delta the node does not hold (stripped from the blob, in a section it does not open, never come) is absent, the commit reading as one without that delta's body (§5). Chunk blobs of large atomic values (spec/data-model.md §6) are not waited for.
- **Order independence**: which parts apply is a function of the parts and other data held, never of arrival order or of which parts came together.
- A thing's **possible admins**, by the role commits the node has applied (a pending one, parked included, gives nothing), of any validity and whatever followed: the least set holding the thing and, with each member, its first admin and any holder named with admin on that member by an edge write a member signed.
- A thing's **possible writers**, by the same data: the least set holding the possible admins of the thing and of each member, and any holder named with write or above on the thing or on a member by one of that thing's or that member's possible admins.
- A request's signers **could hold the right** of a delta's purgeable-by when its author and its actor each could, by any role any held write ever gave, whatever that role's validity: for `admin`, a possible admin of the thing; for `writer`, a possible writer of it; for `author`, the delta's actor or a possible writer of that actor, the actor being a possible writer of the thing; for `author_or_admin`, either of the `admin` and `author` cases.
- A delta of an already applied commit that arrives later (a blob of the commit holding more parts than the node applied: the node began syncing its label after applying, or its body counts as never received, §5) is joined on arrival; a blob holding fewer changes nothing.
- Role commits are applied before content.
- Two commits of one session whose counter ranges on one aspect overlap are both invalid.
- **Judged alone**: a fault of the header or signature refuses the commit, in any copy. Each delta is judged by itself, from the signed header, its bytes and held data; its fault never refuses another delta:
  - Bytes that do not match the header's delta hash, or a part index naming no aspect, are not that delta: dropped, and any copy matching the hash is taken as if they never came. A blob holding nothing else is bad input.
  - A part on an aspect of the wrong storage class (§2) is dropped.
  - A delta that matches and is bad by itself never applies. Only those bytes can match, so nothing marks it: it is judged again if it comes again. Bad by itself means:
    - it does not decode;
    - a `created.0` delta that is not one minting of its record;
    - a `roles.0` write inside an entry it did not create, or a value that is no well-formed grant (spec/permissions.md §2);
    - a value held unchunked that spec/data-model.md §6 chunks;
    - a carried write stamped after its commit.
  - A blob holding only such deltas, none of its parts waiting, is bad input.
  - Where such a delta, or its commit, waits, the delta is judged when that wait ends.
- **Copies**: a commit pending for `ts` past `MAX_DRIFT` is held before its deltas' hashes are checked.
  - A pending commit keeps the first copy of each such delta and of the signature.
  - A copy that proves not to match goes, and a node then judges again the copies of the commit it holds as blobs; this brings back no delta counting as never received (§5).
  - A copy it no longer holds comes back as a holder's new upload (spec/sync.md §6).
- A commit blob whose clear prefix disagrees with its header (expiry, the commitments to the delete keys its deltas list; spec/sync.md §1) is bad input.

## 5. Retention and purge
Every delta carries **retention** on the wire: who may purge it and what happens to its history once it is replaced; its commit carries its expiry (§6). The writer fills both from the schema's defaults per AK (spec/data-model.md §2); a commit may set retention per aspect; an untyped write (no schema for the AK) defaults to `author_or_admin` with no history promised and no expiry. Retention is immutable: to change it, purge and write again.

### Who and how long
- **Purgeable by**: a set, not a scale: `nobody` (none), `admin` (the thing's admins), `author` (the delta's author), `author_or_admin` (both), `writer` (every writer, so both too).
  - A `nobody` delta shares a commit only with `nobody` deltas, `required^.0` aside, which goes with any (§6).
  - No exception widens it: a body whose set has no holder stays until its expiry, if any.
  - A member of the set may drop the delta's body: by purge request (spec/permissions.md §6), by compaction, and by deleting its blobs at hosts (spec/sync.md §5). Delete keys follow it (spec/crypto.md §7).
  - A **right holder** is a node that holds the right now.
- **History**: one of
  - none given (the default): no history is promised;
  - **keep history** until an absolute time T and/or for a duration D after the body is replaced, the later counting; T = 2^63 - 1 is **forever**; D = 0 or a T already past is the same as none given;
  - **purge on replace**, only under `writer`.
  - A `nobody` delta keeps history forever; any other history under `nobody` is refused.
- **Keep bounds**: keep history is a **keep at least** of T and of D after the body was replaced (the later counts); a role-class body has a keep at least of `ROLE_KEEP` after replaced (Fixed retention). Purge on replace has no bound: it is a duty to cover (Purge on replace).

### Bodies and deaths
- Principle: a body drops in one of four ways: as covered (a valid compaction snapshot whose commit holds the right over the body covers it, or its author's own whole replaces do, Covered, Own replaces, Between the bounds), by expiry (§6), by purge request, or as invalid (Invalid, below). A signal's body is in no state, so nothing covers it: past its keep bound it is past every bound, and a node may drop it (Signals). A node drops nothing else on its own; one without write on the aspect writes no snapshot, so it drops only expired and invalid content, what a writer's snapshot covers and what an author's own replaces cover (Own replaces).
- A **body** is the commit's blob (spec/sync.md §3): its held deltas, each in its thing's section; a rewrite holds fewer. Keep bounds are judged per retention class (retention and delete keys) of its deltas.
- A write **dies** when a later write supersedes it or at its delta's expiry (spec/crdt.md §4.8). A **live write** of a body is any write of its deltas the node's state holds by dot, resets and value-less writes included, and every sequence element record of its deltas the state holds, also one holding only others' writes. An element's or entry's tombstone is not one of its creator's (it holds the remover's reset, not the creation). A held valid body is **replaced** when it holds a write the node's state does not hold and joining it into the state leaves the state's canonical bytes unchanged (spec/crdt.md §3.3): the write is dead, not un-merged (spec/crdt.md §4.6). A delta with an expiry held with its values is judged against the state holding them value-less, as a snapshot carries them (spec/crdt.md §8): it is replaced only once none of its values lives.
- When a body with a relative keep at least was replaced is a function of the bodies the node holds, judged when asked:
  - a write of the body that the node's state supersedes (it wins in the body and not in the body joined into the state, spec/crdt.md §4.8) died at the `ts` of the earliest held valid body holding a write that supersedes it (spec/crdt.md §4.8: its superseder's own commit, or a later snapshot carrying it); with no held body holding one, at its superseder's `ts` as the state holds it (a valid snapshot's copy of a delta invalid here: the earliest held valid snapshot's `ts` holding it);
  - a delta's body is replaced at the earliest death of its writes, a snapshot's at the latest death among the writes it carries that no held valid snapshot stamped later with at least its D carries (holds as a winning write, the same position, kind and stamp, spec/crdt.md §4.8; it keeps the history of each such write for D after that write died; a later snapshot keeps the others'); none such dead: past the bound;
  - so never earlier than the death (spec/crdt.md §4.8); nodes holding the same bodies judge alike, and one holding more judges no later;
  - an expiry dates none: the delta's body goes at T (§6) and a snapshot holds the write value-less;
  - a write of a delta invalid here does not die, nor does a valid write an un-merge took with nothing superseding it (spec/crdt.md §4.6).

### Covered
- A body is **covered** by a valid snapshot the node holds (spec/permissions.md §5.2) when joining each of its deltas into the snapshot's fragment of that aspect leaves its canonical bytes unchanged (spec/crdt.md §3.3): every live write of the body is in the snapshot, and canonical form carries no dead content. A held body is judged by this join whatever the snapshot's tables say.
  - A node MUST NOT count a body covered unless the snapshot holds each live write of the body with the body's payload: a copy held with another payload leaves the body uncovered whichever wins the copy order (spec/crdt.md §4.1). A value-less write of the body (spec/crdt.md §4.7) is judged by the join alone.
  - A snapshot body is covered only if it is stamped no later than the covering snapshot.
  - A snapshot that purges on replace covers no body that keeps history while the body has a live write (Keep bounds): it cannot keep that write's history.
  - A valid snapshot body's copies all count in the join (spec/permissions.md §5.2); an invalid one's copies of writes whose own delta the node received and judges valid are left out of it.
  - A body the node cannot join, a snapshot whose pages the node has not fetched, or a snapshot body it has not received (a late part, or one counting as never received again, spec/permissions.md §5.2) establishes nothing: the body is neither covered nor uncovered for it (spec/sync.md §6).
  - A body holding no delta is covered (a lasting header is must-hold all the same, spec/sync.md §6), unless it is session-form and the snapshot's frontier has an entry for its session short of its counters (no entry: the snapshot holds no write of the session, spec/crdt.md §8).
  - A delta with an expiry held with its values is judged by the join like any body: a snapshot carries its values value-less (spec/crdt.md §8), so covers it only once none of them lives. One not held is not covered until the node holds it value-less (past T, spec/crdt.md §4.7); from then on its leftover is judged by the join.
  - A snapshot written from a node's whole state of an aspect covers every body of it the node had applied, except a delta with an expiry holding a live value.

### Own replaces
- A **whole replace** is a plain durable content commit on a content aspect (not signal, not ephemeral) whose delta resets the aspect at its root (a root reset or a root register write, spec/crdt.md §5.1); it may carry an expiry. An **own replace** of an earlier plain content commit C is a whole replace of the same author (an account's devices are one author), `ts` later than C's, valid and held here, that passes the covered test of §5 Covered with its delta in place of the snapshot's fragment.
- C drops as covered by an own replace once two own replaces of C are held valid here: the writer's previous replace stays until the next lands, so a replace that later counts for nothing costs what it alone carried. Which commits cover C is a function of the commits held: the same at every node holding the same commits.
- A commit with several parts goes under own replaces only whole: every part it still holds must be covered by own replaces whose author holds the right over it, and it goes once the latest of the parts' keep-at-least bounds passes.
- A body not held and not dropped (not fetched yet) is not established as covered; a dropped one joins nothing and is.
- An own replace drops C only where its author holds the right over C (Between the bounds), which every node reads alike: every node, reader or writer, drops C under own replaces once its keep-at-least bound passes (`MAX_DRIFT` past it), as under a snapshot it holds the right for, and judges C covered for must-hold (spec/sync.md §6) by the same test.
- An own replace that turns invalid, or drops other than as covered, gives nothing: a commit dropped under own replaces stays dropped only while two of them (or a valid snapshot covering it) are still held valid; otherwise it is missing again, as under a snapshot (spec/permissions.md §5.2).
- A delta with an expiry is judged by the join, not by its own lifetime: a later own whole replace covers it whether its values have expired or not.

### Forgetting
- A node forgets a durable content commit, header and ID included, once every part of it dropped as covered by a cover of its own author (a compaction snapshot or an own replace) and no entry of a blob of it is known and no delete of one is within `TOMBSTONE_LIFETIME`.
- Kept: role commits, a thing's first commit (its `created.0` part never drops), a lasting commit, a commit carrying a purge request, a compaction snapshot.
- A node keeps, per aspect, the newest `ts` of a commit it forgot there, across restarts: an undo counts what that commit may have held (§7).
- Forgetting reads as never having received it: a demotion frontier cannot list it (spec/permissions.md §5.1), and its author's cover stands for it. A forgotten commit arriving again applies and goes again by the same rules.
- Limit: a cover that later counts for nothing (a removal that does not list it, an addendum that falls) cannot give a forgotten commit back. Loss is bounded: a snapshot or own replace that reached a node before the removal's `ts` still counts for what it carries.

### Keep bounds
- **Keep at least**: before the bound (T, or D after the body was replaced, Bodies and deaths) a body leaves the labels of its things' groups only by purge request or expiry, and a node only by those or as invalid: compaction MUST NOT drop it, right holders MUST NOT delete it at hosts. A body with no dead writes is past a relative bound. A node judges the bound alike whether it may write or not.
- On a commit carrying a purge request every body is kept at least until the purge floor (below), judged by the node's corrected clock.
- **Purge on replace**: a node that may write the aspect and holds a replaced purge-on-replace body that no held valid snapshot holding the right over it covers MUST write a compaction snapshot of the aspect from its whole state in the transaction in which it comes to hold one (applying the replacing write or the body, a validity change, or a role change making it a writer); duplicates from several writers are harmless (spec/sync.md §7). Every node MUST drop a held purge-on-replace body that a held valid snapshot holding the right over it covers, as soon as it holds both. So the body is gone at every writer holding it in the transaction it learns of the replacement, and everywhere else when such a writer's snapshot arrives; a node without write keeps it until then, for good if no writer holding the body and its replacement ever syncs. A snapshot carrying a purge-on-replace write live purges on replace itself (Fixed retention), so its copy goes the same way. If the replacing write later turns invalid, the valid snapshots carrying it vouch for it (spec/permissions.md §5.2, Copies): the replacement stays and the replaced body does not come back.
- A waiting part (§4), parked included, keeps its body until it applies, whatever its retention: before that only a purge request or its expiry acts on it (below). Limit: one that never applies is kept until one of those does, or for good.
- **Invalid**: a node drops a held delta it judges invalid at the end of the transaction that judged it, whatever its keep bounds, but for the deltas spec/permissions.md §6 keeps. While it stays invalid a copy arriving again is not taken; once valid it counts as never received from then on, and the node fetches it again (spec/sync.md §6 Dropped bodies).
- **Never received**: a body dropped other than as covered, invalid or past a signal's keep bound (a part missing when purged) counts as never received from then on.
  - The node does not fetch it on its own.
  - A copy that arrives again joins as a late part and is judged again.
  - Its holders upload it while it is must-hold (spec/sync.md §6), so nodes holding the same bodies read alike.
- **A waiting part past its expiry**: a part that waits (§4) when its expiry passes goes from the node at T, and one arriving past T goes if it waits. Either counts as never received: its non-value writes join only through snapshots. Every local copy goes with it. That node may read what came before the part until it holds a writer's next compaction while that counts (spec/sync.md §7; one dropped while it did not count repairs nothing until it comes again, Invalid); a commit such a part applied before T stays applied.
- **A waiting part under a purge**: a waiting part that an applied purge request names whose author may purge it (judged once the node holds the request and the commit's header) is held value-less from then on.
  - The node keeps it as its leftover (spec/crdt.md §4.7) and no other local copy of it; it waits and applies as that, so nodes holding the same commits read alike.
  - With a page of it not held, or parked (spec/versioning.md §2), it cannot be stripped: it goes at once with every local copy, as a part missing when purged.
  - If the request no longer drops it when its commit applies, it is fetched again like any missing delta.
  - A snapshot part has no values of its own: it waits unstripped and drops once applied.
- For any dropped delta (here or below), a received blob holding it that may also hold the only true copy of a waiting part of the same commit (one whose slot a copy not yet checkable holds, §4 Copies) is kept until that copy is judged.
- Where such a drop may leave a node reading less than one that kept the data, it reports the aspect suspect (spec/permissions.md §4).
- **Between the bounds** a right holder may drop a covered body (compaction, spec/sync.md §7) when the covering snapshot's own commit holds the right over it, as a purge request would at that snapshot's key (spec/permissions.md §6), and the node itself holds it now. A snapshot without the right carries the body's live writes and covers it for must-hold (spec/sync.md §6) but drops nothing, at any node. `nobody` makes that window empty. Snapshot bodies follow the same rules.

### Signals
- A delta on a signal without `+` (spec/data-model.md §2) is never joined into a state, and no compaction snapshot carries or covers it. It is **replaced** the moment it is written: its body is history from its own `ts`.
- Its retention is keep history (in its wire form, spec/wire.md §4); a writer MUST NOT write one with none given or purge on replace, and such a part is bad (§2).
- Keep bounds apply unchanged, D counting from its own `ts` (Keep bounds); T forever keeps it for good. Before its keep at least and any purge floor end it leaves only by purge request, expiry or as invalid.
- Past that bound it is past every bound: a node may drop it, whole or as its leftover. A node takes no copy of it past the bound, fetches none (one dropped as invalid that turns valid, or held value-less for a purge that falls, stays dropped: never missing again), and holds none as must-hold (spec/sync.md §6). Whether a node still holds it changes no read: it is not listed (§7 Listed parts).
- Expiry (§6) and purge requests apply to it per delta, as to any delta.
- **`replaces`**: a delta names a fire it replaces (§1, spec/wire.md §4). It is **honored**, judged from headers alone, when the named commit O is listed on the same `(t, ak)` and valid (a purge tombstone counts), carries no `replaces` on that aspect, has the same verified `actor`, and sorts before the delta by `(ts, ID)`; else the delta is a fire of its own at its own place.
- A listed original's part reads as its newest listed honored version by `(ts, ID)` whose body the node holds or that is purged, valid versions only, else as itself; its stamp, place and order stay the original's. An honored version is not listed of its own. A node's own invalid part is marked and reads as itself.
- A writer gives an edit O's `expires`, and writes `replaces` only naming a fire it would honor if written now: its actor's own, listed and valid there, carrying no `replaces`.
- Listeners hear a write only as a listed commit (§7 Listed parts): told, at the end of each storage transaction, of every commit whose listed part on it reads otherwise after it (applied, joined late, turned valid or invalid, purged, dropped). A commit that leaves the listing and shows again is told again. An honored version is told as its original's change, and itself only when it is listed of its own before or after (it arrived before its original, or stands alone once its original is not listed).
- A validity change rebuilds no state for it: it changes only which of its bodies are valid (spec/permissions.md §5.2), and so its history.

### Required retention
- **Required retention**: `required^.0` (spec/data-model.md §9) has, in `rules`, AKs mapped to a purgeable-by, a history and an optional expiry duration, in `default` an optional entry of the same form, and, in `retain`, the default for removals (spec/permissions.md §2), read in force as the rules are.
  - A delta answers to it unless it is a compaction snapshot's or its aspect has fixed retention or is not durable.
  - The setting **in force** at a key is what the newest valid `required^.0` delta the node holds on the thing ordered strictly before that key (by key, spec/permissions.md §5.1) says, each judged as an admin-only delta at its own key (spec/permissions.md §5.2); none: nothing is required.
  - The entry governing an AK is its own in `rules`, else `default`; neither: nothing is required.
  - A delta **breaks** an entry that governs it if it does not carry exactly the entry's purgeable-by and history (in its wire form, spec/wire.md §4: a keep with `after` 0 is none given, one with neither bound too), or its commit, with a duration, does not have `expires` = `wall_ms(ts)` + that duration (a `replaces` delta: `wall_ms(ts)` < `expires` <= `wall_ms(ts)` + that duration) or, without one, has an `expires`, or it carries `replaces` under a `final` entry.
  - A delta that breaks the setting in force at its key is invalid; its commit's other deltas are judged on their own.
  - Each `required^.0` delta is read alone: its value is the whole setting, and a delta not reading as the aspect's type, with a key in `rules` that is not an AK (spec/data-model.md §2) or with more than `MAX_REQUIRED_ENTRIES` entries in `rules`, requires nothing.
  - A writer fills the required retention and expiry and refuses others, writes `required^.0` whole (never by path, within those bounds, with no entry a write could not meet) and does not undo it.
  - A change judges only later keys; it rewrites no delta's retention.
  - Limit: no snapshot carries a `required^.0` delta (§2), so one dropped as invalid that turns valid again comes back only as a copy (spec/permissions.md §6 Invalid deltas); until then the node judges its thing's later deltas without it, whatever a writer compacts.

### Purge
- **Purge request**: a header field naming earlier deltas (of commits with a smaller `ts`; a later one is not named, but for a minting: an item on `created.0` names every minting of its thing, §5 Ending) by commit, by a whole aspect history, or by author on an aspect (spec/wire.md §4). It names only deltas with writes of their own, never a compaction snapshot's. It MUST NOT name role-class deltas.
  - A later-arriving delta an applied request names falls under it as one held does.
  - Every node applying it drops, at any time, the named deltas its author may purge (spec/permissions.md §6): from then on it holds their value-carrying writes value-less (spec/crdt.md §4.7) and holds each named delta's own body and every body carrying their values as its leftover (spec/crdt.md §4.7 Copies: snapshots carrying a copy under the named delta's dots), whatever the order the request, the named delta's commit and the carrying body arrive in. A snapshot has no values of its own and is never named, so a purge never drops one and never shows one as purged; its copies of the named deltas' values go as any carrying body's. A node judges a named delta once it holds the request and that commit's header (which the right and the writes it names depend on).
  - A writer that, after applying it, holds no covering snapshot of the aspect under a label it writes re-snapshots there (duplicates are harmless, spec/sync.md §7).
  - A request SHOULD name dead writes; the writer resets live content in the same commit.
  - A commit carrying a request has a delta on each thing it names (it is what places the commit under the thing's labels): where no reset is wanted, a write of `purge.0` (spec/data-model.md §9), which carries no `expires`.
  - A commit carrying a purge request and an `expires` reaches only deltas of commits whose `expires` is at most its own (a delta with none is beyond it); a writer refuses one that names anything else. Its blobs are kept at least until `wall_ms(ts) + ROLE_KEEP` or its `expires`, the earlier, whatever its deltas' keep bounds.
- **Purging drops bodies, never headers**: a node keeps the header of every durable commit it applied, until it is forgotten (Forgetting).
  - An ephemeral commit goes whole, header included, once none of its deltas is held and none waits: covered or superseded (spec/sync.md §9); an expired one is held as its leftover. A copy arriving again applies again and goes again by the same rules.
  - A node dropping a body for a purge keeps the commit as a blob without the purged deltas: same header and commit ID, new blob, held and uploaded like any body. With none left it holds only the header.
  - A **header-only blob** goes under a label only as a lasting header (below); its prefix has no expiry and no commitments.
- A delta is **permanent** when it is durable, its aspect has no fixed retention, its retention keeps history forever, and its commit has no `expires`. Only a purge request removes its body.
- A commit is **lasting** on thing t when either:
  - a permanent delta of it on t is dropped;
  - its purge request has dropped a permanent delta on t at this node (spec/permissions.md §6: its author held the right, as the node then judged; a request that falls stays lasting there).

  A lasting commit's header is never forgotten, and every label of a group with t in its closure, whose actor may read t, holds a blob of the commit for good (spec/sync.md §6): a body of it, else a header-only blob. A purge of any other delta leaves nothing at a label. The commit reads as a held commit without that delta's body: its author, actor, `ts` and retention stay, and whether to show it is the reader's choice.
- **Dropping a body** means destroying every local copy, its delta nonce and every local index entry derived from it. Holding one as its leftover destroys every copy of its values the same way; the leftover is a local body (never uploaded, deleted at hosts as a dropped one).
  - What the part was judged stays: its validity, the role its writes needed, and for a `secrets.0` or `keys.0` delta the epochs it boxed or keyed, whose introducing commit spec/crypto.md §4 asks for, and the sealed names of its boxes to the holders its edge writes put, a grant's.
  - A leftover holding no value of its own writes (expired, purged) is never dropped for keep bounds; past its expiry it drops as covered (§5 Covered); a purged one is not dropped as covered. Otherwise it goes only with its thing (spec/permissions.md §3), as invalid, or for a copy of its body that holds values again (a fallen purge). A body held as its leftover only for the copies it carries is a body like a whole one for keep bounds and covering.
  - Exception: a compaction snapshot's part dropped other than as covered still counts for suspect flags (spec/permissions.md §4) from its header alone; a part dropped as covered need not (its coverer is valid and stamped no earlier). One held as its leftover is held.
- A dropped body cannot be undone (§7); under purge on replace others' resets beat undo.

### Fixed retention
- **Fixed retention**:
  - role-class deltas and `addenda.0`: `admin`, no history promised; each node keeps a replaced one `ROLE_KEEP` after replaced (a keep at least, §5 Keep bounds: compaction snapshots or later writes replace them; `roles.0` is never compaction-snapshotted, §2, so its deltas stay);
  - `required^.0`: `nobody`, history kept forever; it is never snapshotted (§2);
  - `purge.0`: `author_or_admin`, no history promised, its snapshots too;
  - a certificate copy carries its commit's;
  - snapshots of role-class aspects keep it.
- Other compaction-snapshot deltas are `writer` (a receiver checks this; the history below is the writer's, from what it holds), with history from the **own deltas** of the writes the snapshot carries live (Bodies and deaths): purge on replace if any of them has it, else kept for the longest D among them (no T), else none given.
- A write's own deltas are its own commits' deltas on the aspect (spec/permissions.md §5.2). For writes whose own commit's header the node does not hold, every held snapshot body of the aspect carrying one of them stands in, and if some such write no held snapshot body carries, every compaction snapshot of the aspect the node applied.
- No schema enters the bounds; a snapshot names the schema of the last applied delta of the aspect in `(ts, ID)` order that names one, else none.

### Ending
- `created.0` has ordinary retention; its schema default is `admin` with no history promised, and a writer gives it `nobody`, history kept forever, in a commit of `nobody` deltas.
- A record is identity and `created.0` is existence: a thing is known by its creation record, from a `created.0` delta or a record blob (spec/wire.md §3), and parts on it are judged by it; when it ends, authority that passed through it stands as its frozen history says.
- A **minting** is a `created.0` delta; it needs no authority (spec/permissions.md §1). A node writes to a thing other than a key actor only while it holds a minting of it: one known by a record alone cannot be told from one that ended.
- A thing whose every held minting is held value-less (expired, or purged by a request holding the right, spec/permissions.md §6) is **ended**. A purge item on `created.0` names every minting of its thing, whatever its `ts`. Its **ending** is the point every minting of it ended, each at its `expires` or at the earliest request dropping it. A request's right to end a thing is judged without the edge writes on the thing stamped after the request. **Nobody writes a thing after its ending**: a part on an ended thing whose commit is stamped after its ending (`wall_ms(ts) >= T` for an expiry, after the request for a purge), other than a minting, is a part on an unknown thing, whatever its aspect. The ended thing: in the same transaction the node drops every part on it as a body (spec/sync.md §5 deletes them at hosts) and its states. It **keeps** its creation record, its value-less `created.0` deltas and its `roles.0` parts (no content) while either holds:
  - it ended by purge: for good, since no rule drops a request;
  - a **dependent** is held: another thing whose authority paths it is on, by a held creation record naming it first admin or a held edge write naming it holder (paths through it climb its record edge and its frozen edges), or, for a key actor, a commit it signed or acted in with a part held on another thing (its record verifies that commit).
- Otherwise it keeps nothing, and every ended actor named on it (its first admin, its holders) left with no dependent keeps nothing then either. Parts on an ended thing arriving later are parts on an unknown thing (§4), but for its `created.0` deltas and, written before its ending, a request's `purge.0` part and, while the record is held, its `roles.0` parts.
- What a dependent needs of an ended actor travels with the dependent: its labels carry the record and the frozen `roles.0` history (spec/permissions.md §4), placed by the dependent's holders, and a node that kept nothing of the actor takes them again when it opens them (a part the ending dropped counts as never received), so it judges a dependent reaching it later as the others do.
- An ended thing reads as absent to every read and write, its held record and request included.
- Nothing else is kept per ended thing but what any drop leaves: commit headers, and the request by the ordinary purge rules. A copy of the creation arriving ends the thing again.
- An ending that falls brings the thing back only where a copy of it is still held or fetchable.
- Limit: anyone holding a thing's record may mint it again, stamped at any `ts` (an honest writer mints once, in its first commit). A durable minting keeps an expiring thing existing past its expiry or brings it back after it, and one whose retention the ending request has no right over (`nobody`, another's `author`) keeps it from ending by purge or brings it back after. It carries no content: the thing's other parts expire and are purged as before, and what an ending dropped is back only where a copy is still held; brought back, the thing takes writes as any live thing, by its roster.

## 6. Expiry
- `expires: T` (wall ms, `T > wall_ms(ts)`, else invalid), one per commit: every delta of it expires at T. A commit carrying a fixed-retention aspect (§5) carries none.
- A writer whose `ts` has reached the T it was given (its HLC ahead of its clock) writes `wall_ms(ts) + 1`.
- The schema may give a default per AK as a duration from the write.
- The blob prefix carries the commit's T (spec/sync.md §1, §3).
- A write is one commit. A delete writes its durable commit only: the deleting node drops the thing's ephemeral state locally (spec/sync.md §9 Sending). A commit creating a thing takes the commit's expiry on its `created.0`, so one commit is a whole thing that expires. A writer refuses, before anything applies, a write whose deltas want different expiries, that mixes `nobody` deltas with others (§5), or that asks for an expiry beside a fixed-retention aspect; and one asking for durable, ephemeral and relay-only writes together (§2, spec/sync.md §9).
- At T every value-carrying write of the delta dies (spec/crdt.md §4.7): every node holds them value-less, the body and every held snapshot carrying a copy of their values as its leftover, whatever the delta's keep-at-least bound.
- A delta never received stays never received: a copy arriving after T joins value-less (held as its leftover from then on), and what a held snapshot gave under its dots goes with the snapshot (spec/permissions.md §5.2).
- Hosts delete the blob at T unattended (spec/sync.md §5).

## 7. Undo
- **Listed parts.** What a node shows of the commits on an aspect (a commit listing, spec/requirements.md API) is the **listed** parts: those in kept history (below), and this node's own invalid parts (marked invalid). A purged part is listed while its writes, held value-less, are in the aspect's current state or its keep rule would keep it had the purge request replaced it (counted from the request's `ts`); it shows as purged. Nothing else is listed, held or not: a body replaced with no history kept, expired, dropped, or another node's invalid part. A commit is listed at an aspect while it has a listed part there.
- An undo commit (a revert) sets `undoes` to the undone commit's ID; its deltas are chosen per spec/crdt.md §4.6 (undoing a creation deletes the thing, so they may touch aspects the undone commit did not). An undo reverts every part of the commit or there is none: a commit with a valid part whose body was dropped (§5: covered, expired, purged) or is not received yet cannot be undone (a signal's part, the creation record, a `required^.0` part (never undone, §5) and parts on the things it created excepted: the undo needs no body of theirs). Redo is an undo of the undo commit. A signal reads absent before and after any write, so an undo writes nothing back for it (a purge request removes its writes, §5). An ephemeral commit is undone by an ephemeral undo commit, from the same kept history (§5) held in memory.
- **Kept history only.** An undo writes back content only from **kept history**: the held valid parts of the aspect ordered before the undone commit that have a write in the aspect's current state, or whose body a keep bound (§5) still keeps. A part neither is left out, whether or not the node holds it.
- Where the undone part's inverse writes back content it replaced (spec/crdt.md §4.6, by its writes' kinds), every part it may have replaced must be kept: each held valid part of the aspect ordered before it (by header, body held or not) is in kept history now, or (held or dropped, not one not received yet) its retention would keep it now had the undone part replaced it (a keep bound counted from the undone part's `ts`), or is superseded by a part in kept history ordered before the undone part: a delta resetting the aspect's root or writing it as a register stamped after it, or, if it has writes of its own and no `expires`, a snapshot whose `Frontiers` reach its counters or whose `Absorbed` lists it (spec/crdt.md §8; a commit they do not name is not reached). An ephemeral commit the node has forgotten (spec/sync.md §9 Forgetting) counts as a part not kept unless such a reset stamped after it is in kept history. Else there is no undo. Limit: one part keeping no history on an aspect blocks such undos of every later part there until a part in kept history supersedes it. The undone part's own retention does not count. An undo only taking away what the part created needs no history.
