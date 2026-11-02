# Evidence for design E
> Summary: Rule citations and traces for chat design E.

"Traced" = read in spec, notes or code. "Estimated" = arithmetic from cited sizes. "Not closed" = inferred, not verified.

## E1 versus E2

- A tid in a value is a bare reference (spec/data-model.md §1); the closure of a group runs through `group.0` and `placed.0~` only (§8, spec/sync.md §3). So E1's message thing reaches readers only when placed in a group whose label they sync and entitled through an actor C may read: a per-member actor again (E1 = C's machinery plus a tid log). Traced.
- E2: a delta on C's own aspect is in C's closure (C is in its own closure, spec/sync.md §2 Home label: "the home closure holds the actor thing and what its group.0 lists") and entitled (C reads itself). Traced.

## 1. The crux: can another member destroy or hide a body?

- Keep at least: "before the bound ... a body leaves the labels of its things' groups only by purge request: compaction MUST NOT drop it and right holders MUST NOT delete it at hosts" (spec/commits.md §5). With `abs` forever (spec/wire.md §4: `2^63 - 1` means forever) the bound never comes. Traced.
- Compaction: a node that may write an aspect drops "the bodies they cover ... that it may purge and whose keep-at-least bound is MAX_DRIFT past" (spec/sync.md §7); "Between the bounds a right holder may drop a covered body" (spec/commits.md §5). Both conditions fail. Traced.
- Purge rights (spec/permissions.md §8): `author` = the thing's current admins plus "the actor directly above the author node in its chain while it holds write on the thing". A non-admin, non-author member holds none. "A purge request drops a named delta iff its author held that right at the request's time"; a request naming every delta is judged per delta ("the named deltas its author may purge", spec/commits.md §5). Traced.
- Deletes at hosts: a level key must match the blob's commitment (spec/sync.md §5 Delete). `author` retention lists levels 1 (C's admin secret) and 2 (the author's account write secret) (spec/crypto.md §7); level 3 (C's write secret, held by every member) is listed only under `writer`. So members must not write `writer`; the display rule hides it. The label delete key is C's admin secret. Traced.
- A reset or a later write: "Writes are never modified, only superseded" (spec/crdt.md §1); a reset prunes state, not bodies; retention dates deaths and the bound decides drops (spec/commits.md §5). Traced.
- Must-hold: "before its keep-at-least bound or established uncovered" (spec/sync.md §6), so a superseded body is must-hold forever and writers re-upload it if a host loses it. Traced.
- A valid writer's snapshot may misstate a held delta in state (spec/permissions.md §5.2); reading history from bodies avoids state. Traced; depends on the history API reading deltas, not state.
- So the crux holds for `author`, `admin` and `nobody` with keep at least forever. It fails for `writer`, or without keep at least (an honest admin's routine compaction would drop every superseded body). Traced.

## 2. Reading history

- No API reads superseded values: `commits(query)` returns headers (`CommitEntry` has no value, notes/api.md Commits); undo buffers hold `UNDO_DEPTH` 16 (notes/growth.md); a watch "holds only the latest value; a callback that falls behind sees every commit's effect but not necessarily one call per commit" (notes/api.md Watching). Bodies are held while retention keeps them (spec/commits.md §5) as blob ciphertext plus wrap in the store (notes/local-store.md Units). Traced; the API is new.
- New devices: a label syncs whole (spec/sync.md §6); every body is must-hold so writers re-upload what a host lacks. Traced.
- Per-commit received time exists in `CommitInfo` (notes/api.md Watching, Commits). Traced.

## 3. Identity and forging

- A commit is pending until its author's chain to the header's actor is held (spec/commits.md §4: "no owner link or holder ... leads from the author to it"), and a delta is valid only if that actor held write (spec/permissions.md §5.2). So the header's actor is verified, not a claim. A device that administers two accounts chooses which it acts for; both are true. Traced.
- Order by `ts`; a node's next commit stamps above everything it holds (spec/crdt.md §2.2); more than `MAX_DRIFT` ahead is parked; backwards is the author's word (spec/requirements.md Permissions line 108). Traced.
- Retention is in the signed header per aspect (spec/commits.md §1, spec/wire.md §4), so "show only the requested retention" reads the header. Traced.

## 4. Kick and leave

- Frontier scope: "every aspect of the things the demoted authority gave write on" (spec/permissions.md §5.1): C's aspects. Deltas not covered are invalid and un-merged (§5.2, spec/crdt.md §4.6); re-grant makes them valid again (§5.2). A deposited or relayed post by the kicked actor is judged the same way, so the deposit fix is not needed here. Self-removal audits nothing; an explicit removal of the absent edge does (§2, §5.1). Traced.
- The kicked device "MUST drop ... every local unit it can no longer read" (§3): its own messages are C's units. Traced.
- Cost: one role commit with C's rotation, 2707 B per holder measured (notes/chat.md Costs); no per-member actor, so no cascade. Traced.

## 5. Delete, expire, edit, reactions

- Purge drops "every body carrying their values, snapshots included" (spec/commits.md §5); with no snapshots that is one body; the header stays ("never headers"); hosts: delete by level 1 or 2 key. Traced.
- Expiry per aspect of the commit, hosts delete at T unattended (§6). Chunks carry the delta's keys and expiry (§1, spec/sync.md §1). Traced.
- Keep at most is only under `writer` (§5), so an edit is a new message plus purge of the old. Traced.
- Reactions and read markers as deltas: attribution from the header or the change event's `CommitInfo`; a keyed state (`map<account, …>`) would be writable by any member, so the app must not read state for attributed data. Traced by rule.
- Tombstone: "A node dropping a body for a purge keeps the commit as a blob without the purged deltas (header-only ...)" (§5); header forgetting (issues/session-sources.md) forgets headers whose parts are purged, hence the marker write. Traced.

## 6. Costs

- Message: a minimal commit is 288 B (notes/testing.md budgets) plus wrap 49 B and host entry overhead; about 0.5 KB. Estimated.
- Join: the joiner's chain certificates about 11.5 KB per label plus the grant; no member actor (5.4 + 2.9 KB in notes/chat.md). About 35 KB, estimated.
- Per-aspect indexes and re-merge: "a change becoming valid again re-reads every held change of its aspect" (issues/node-core-gaps.md); un-merge of a register winner "needs the retained bodies" (spec/crdt.md §4.6). Not measured for 10^5 to 10^6 bodies; per-year aspect names bound it. Not closed.
- Frontier: per (tid, ak, node) today (spec/permissions.md §5.1), one entry per aspect and device; under issues/session-sources.md 32 B per uncovered commit; a snapshot of a register covers every superseded body ("joining each of its deltas into the snapshot's fragment leaves its canonical bytes unchanged", spec/commits.md §5) without dropping any (keep at least). Traced by rule; the interaction with the session design is estimated.
- Residue 33 B per expired or purged delta (notes/growth.md). Estimated.

## 7. No member list

- An actor "MAY be synced as a group of itself" (spec/sync.md §2 Home label); `sync(group)` gives a group its own label (notes/api.md Sync configuration). An empty `group.0` lists nothing; the label still carries C's own aspects. Members are C's roster (`roles.0` read as the timeline's roster, spec/permissions.md §2). Traced.

## 8. Forward secrecy

- Every message is a content blob under C's one label; D's chain wraps content blobs under the hour key and leaves role commits under the read secret (d.md); nothing in E needs an old content key. Traced against d.md.

## 9. Rules leaned on

- Promised: retention bounds and purge rights per edit (spec/requirements.md Deletion lines 54, 56). Not promised: a history read API. "Nothing depends on retaining full history" (line 62) is about osis, and E chooses retention that keeps it. Traced.
- Hostile junk under `nobody`: nobody may purge (§8), must-hold forever (§6), and validity is no must-hold criterion; hence the proposed admin purge of invalid bodies. Traced by rule; the rule is new.
