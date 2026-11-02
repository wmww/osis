# Review of chat design E
> Summary: Independent review: at honest nodes no non-admin can destroy another's message, and the topology holds, but the sender is unverified without a display rule, kicks and device removals cost one commit ID per surviving message, any snapshot then hides a kicked member's past, and new devices get no tombstones.


Read only, nothing run. Numbers marked "extrapolated" scale measured figures linearly.

**Biggest results.** The crux holds at honest nodes. Three things in the design are wrong: the sender is not verified, the frontier cost is already 34 B per commit and no snapshot can safely reduce it, and a new device gets no tombstone.

## 1. Can a non-admin destroy or hide another's message?

**Mostly CONFIRMED for destroy. REFUTED for "nobody can hide" on one host-level path.**

- **Must-hold: CONFIRMED.** `abs` forever never passes (commits §5, sync §6). `must_hold` keeps the body while `before` is true (core/node/src/sync/pass/mod.rs:1254), even when covered (converge.rs test "closure covered before keep-at-least").
- **Hostile snapshot: CONFIRMED harmless to bodies.** It is valid and not a carrier only, and it can cover. "Between the bounds" fails, and `drop_covered` stops at `due > now` (core/node/src/sync/local.rs:123). A misstatement touches state only. But see item 5: covering does hide a kicked member's history.
- **Right holder for `author`: CONFIRMED.** Admins, or a node with write on the header's actor while that actor holds write on C (core/perm/src/purge.rs:33). A whole-aspect purge is judged per delta (retention/mod.rs `purge_allowed`). A reset or an earlier or later `ts` affects state and order only, never bodies.
- **Deletes at hosts: CONFIRMED.**
  - A writer holds C's read and write secrets, so level 3 only, and `author` blobs commit no level 3.
  - Level 2 is the write secret of the header's actor (labeling/blobs.rs:391). That is the member's account, not C.
  - The label delete key and level 1 come from C's admin secret, which is admin only.
  - A non-admin has no other route. One exception: a former admin who is still a member keeps old admin secrets and holds the head's sync key, so it can level-1 delete bodies from before its demotion. Honest nodes then do not re-upload for `TOMBSTONE_LIFETIME` (sync §6, no live write), so new devices miss those bodies for 30 days. Narrow.
- **Own retention: CONFIRMED.** A member can only misuse retention on its own messages.
- **New, not E-specific: wrap poisoning. Read, not run.** Any writer can re-upload a held blob ID with a garbage wrap and a valid stamp, and the host replaces the wrap (sync §5).
  - A node that knows the key ignores it (core/node/src/sync/inbound.rs:185-195).
  - A fresh device takes it (`known` is None), cannot unwrap, and does not fetch (inbound.rs:262).
  - Holders do not repair it, because the host still lists the entry. I found no repair path.
  - So one member can hide any message from new devices. The per-entry rate limit does not help against one shot. Design C has the same hole. It needs an issue.

## 2. Reads

**CONFIRMED, with API gaps.**

- Superseded bodies stay stored and decodable; un-merge already reads them (crdt §4.6). Nothing drops on a register write.
- Automatic compaction is not wired today: `compact` has no production caller in core/node, core/osis or core/engine that I could find. notes/sync.md line 91 describes it. If it is built, it must skip these aspects.
- "New devices never fetch compacted headers" is about bodies already deleted at hosts. Here nothing is deleted, so a new device fetches every blob. It can, since all are must-hold and writers re-upload what is lost.
- Hosts serve any entry. They do not know about winners.
- Validity per delta exists (`valid_at`). `CommitEntry` exposes neither validity nor value, so the new API is needed as the design says.
- The API must also cover memory commits: `commits()` lists only this session's own ephemeral changes (notes/api.md).

## 3. Topology

**CONFIRMED by rule and code, not run with a burned owner.**

- `closure(g)` is "itself and every thing it contains" (engine/groups.rs:97). sync §2 Home label and the contact card (sync §3) use this exact shape: a group of itself with no items.
- Entitlement holds, since C reads C.
- A member learns the label from the grant's inbox payload, then its home-label copy.
- Nothing is cross-published to an owner's home, because the burned key has none. Founders find C through their own grant copy, as in design C.
- Members need no `sync` call. The first admin calls `db.sync(C)`.
- A member's reset of `group.0` cannot remove C's own aspects. A member can add items and create things owned by C: spam, not hiding.

## 4. Sender identity

**REFUTED as written.**

- `actor` is not verified. Validity uses `h.author` only (core/engine/src/apply/validity.rs:722-723). Wire §11.2 says receivers "reject none for its header's actor", and notes/client-port.md line 57 calls it attribution. The evidence's commits §4 citation is about the thing's chain, not the actor's (apply/mod.rs:489).
- So member M's node can post with `actor = Q`. It is valid everywhere and reads as sent by Q, and only Q or an admin can purge it. The same goes for reactions and read markers.
- **Fix: a small display rule.** Show a sender only if `role(author, actor) >= write` and `role(actor, C) >= write` just before the commit, which is `via_author` in purge.rs:33. The history API should return this as a bool. Every node can compute it from chain certificates.
- With the rule:
  - Several actors: fine.
  - A node administering an account: true by design.
  - A thin client: passes, and a post after the client's demotion fails the rule even though it stays valid (notes/client-port.md line 115).
  - A team: the sender is the person, through T. A team admin removing that person audits its chat posts too.
- **Gap the rule does not close.** A kicked account P1 whose device still reaches C through P2 does not fall (permissions §5.1 step 4), so the kick does not audit it, and a post backdated before the kick passes.
- Sealed sender: **CONFIRMED.** The header is encrypted, the stamp is under the shared write key, and commitments are blinded.

## 5. Kick

**Rules CONFIRMED. Costs REFUTED.**

- Invalid bodies stay must-hold forever. `must_hold` never reads validity, so they are also re-uploaded.
- A backdated post is invalid at every node holding the kick, in any order, since its fresh commit ID is unlisted (permissions §5.2).
- A lost pre-kick post is a small problem. Only the kicked member's own posts are at risk, in the gap between pre-sync and stamp. `Required` fails after `PRESYNC_WAIT` (30 s) rather than stamping. `Skip` or `Try` lose everything since the last sync.
- **The frontier is commit IDs today**, not 10 B ranges (permissions §5.1, data-model §9 `frontier`, core/engine/src/apply/receipt.rs:163). That is about 34 B per commit, reactions included.
  - 10^5 messages: 3.4 MB of linked blobs, plus 2.7 KB per remaining member. At 200 members about 3.9 MB per kick and about 780 MB of host egress. Today's claim was 540 KB.
  - Hard limit: the header's frontier resolves under `MAX_LIST_BYTES` of 8 MiB (core/commit/src/lists.rs:87, apply/mod.rs:280), about 2.5×10^5 commits. Past that, receivers cannot resolve the kick. I did not trace the error path.
- **The one-value snapshot is REFUTED as a remedy, and is itself a hazard.** It drops nothing, but `covered_here` leaves covered commits out of the frontier (receipt.rs:80-98), and an unlisted commit is invalid (§5.2). A snapshot carries only the register's winner, so everything superseded goes invalid.
  - Result: after any snapshot, a kick hides the kicked member's entire earlier history.
  - Any member can write that snapshot just before a kick. So a member can cause another's messages to vanish, given an admin's kick. Re-adding revives them.
- **Required fix:** permissions §5.1 and `covered_here` must not leave out a commit before its keep-at-least bound. The frontier is then O(messages) forever.
- **Device removal is worse than a kick.** Removing a device from an account has the same scope: every thing the account gave it write on, so every chat (§5.1).
  - Each message from that device needs listing. An unsynced chat loses that device's posts (§5.3).
  - The frontier is a chain certificate placed under every label the account writes to (issues/frontier-certificate-cost.md).
  - Routine phone replacement, not rare moderation, triggers this. Compaction cannot shrink it here.
- **Possible core fix, for the owner:** per-session hash chains, where each commit names its session predecessor and the frontier lists heads. Costs 32 B per commit, and frontiers fall to 32 B per session.

## 6. Scale

**Design's bound REFUTED: per-year names bound only the re-merge.**

- Legal AK: `chat:msgs:y2026.0` fits the grammar. Undeclared years go untyped, and each commit sets retention explicitly.
- Open is O(all commits), sync is per label, and frontiers span all aspects, so yearly names help none of these. Busy chats pass 10^6 a year anyway.
- Budget (notes/testing.md) is 10^4 commits per aspect. Extrapolated from there to 10^6:
  - open about 6 s (budget 1 s);
  - first sync about 15 min (9 s at 10^4);
  - revalidation (re-adding a member, or a fallen winner) rebuilds the aspect, about 70 s under the engine lock (719 ms at 10^4 is the old replay figure, issues/node-core-gaps.md);
  - write and sync pass stay fine (about 0.4 ms, about 5 ms).
- Store: about 1.2 KB per message (body plus about 690 B header row, notes/growth.md). Headers cannot be forgotten while bodies are held. Memory at 10^6 is UNVERIFIED.
- **Hostile 10^7 messages.**
  - About 5 GB at every member, and host caps refuse uploads, so the chat stalls.
  - Kicking does not free it (must-hold).
  - Admin purge: about 75 B per item, at most 8 MiB per list, so about 1.1×10^5 items per commit, about 90 commits, 750 MB, kept 90 days. `[tid, ak]` would wipe everyone.
  - Afterwards each old device keeps 33 B per delta for good (330 MB), plus headers until forgetting ships. Open is slow until then.
  - `nobody` cannot be erased without the new rule. No per-member rate limit exists.
  - **Suggest a purge item by (aspect, author).** Without it a hostile member can make every member's node slow for a long time.
- A stream of hostile snapshots re-judging all bodies: UNVERIFIED.

## 7. Moderator delete

**Delete CONFIRMED. Tombstone REFUTED for new devices.**

- Purge commit: one small item. Hosts delete by level 1 or the label key.
- One blob per message holds only if the commit touches one aspect of that retention class. A commit with two aspects of the same class shares a blob (sync §3), and a purge then rewrites the blob.
- Attachments go too (`dropped_chunks`, core/node/src/sync/pass/delete.rs:665).
- Tombstone: header-only rewrites are may-hold, so "nobody uploads it" (notes/sync.md line 33, commits §5). Only devices that applied the message see one. New devices and later members see nothing once the purge commit is gone. Old devices lose it at header forgetting. Devices disagree until then.
- If tombstones matter, the marker write must be the default, not a setting.

## 8. Other limits

**CONFIRMED.**

- Reactions cost the same as a message, plus frontier, for good. Un-react is a purge plus residue.
- Read markers need attribution from held memory commits per author, with no API today. A map keyed by actor is fakeable. At thousands of members: about 0.5 KB per device held in memory per chat (about 1 MB at 1000 members, 2 devices each), plus fan-out to every subscriber. Same order as design C.
- Typing: same sender rule.
- Channel readers cannot react, since a reaction needs write on C. Only a sister chat solves it.
- After a kick the sender cannot purge (no right, no sync key). Admins can.

## 9. Segments

**Works, with gaps. CONFIRMED that the newcomer cannot read C1, and the 15 MB per 1000 members.**

- **Concurrent kick.** Admin B kicks X from C1 while admin A makes C2 with X in it. X stays in C2. A concurrently demoted admin stays admin of C2. Rule needed: on seeing `next`, any admin re-applies roster changes across segments.
- **Kick** is k separate commits with k rotations and k pre-syncs (commits §2: one edge, one target). A kicker stopping midway leaves the member partly in.
- **Links.** A link made on C1 still admits to C1 only, with history and no C2 grant. Old links must die at each segment. The design doesn't say.
- **Left-behind member.** It can tell: it reads `next` on C1 and holds no C2. So the app can say "ask an admin" rather than go quiet. Inbox re-sends help.
- **Re-post.** It is a second commit with the same author, so old members see a duplicate unless the app dedupes by reference and same sender. Two devices may both re-post. Simpler to drop it: a late post stays in C1. The newcomer missing it is what "no history" means.
- **Stitching** is simple: union of reachable segments, sorted by time. Settings need a rule (newest wins). Forks show different conversations to different newcomers: confusing but rare.

## 10. What users would find weird

1. Replacing a phone can make that device's old messages vanish or cost megabytes in every chat (item 5). Most serious.
2. A new device downloads the whole chat with no paging, and the label replays whole, so recent messages are not guaranteed first.
3. Tombstones differ by device (item 7).
4. A kicked or leaving user loses its own messages at once (permissions §3). Design C keeps them. Without the keep policy this surprises people.
5. Two messages in one `Write` batch keep only one, since one delta per aspect holds one register value (commits §1). Queued sends must be one commit each. Also, an edit must check the old message has the same sender, or a member can "edit" another's message on screen.

**Against design C.** E is better on rights: moderator delete, no add-only list, late posts stopped, smaller messages (0.5 KB against 2 KB), smaller join. C does what E can't:
- a sender bound by validity (M's owner) rather than a new display rule;
- compaction, with old text gone on edit;
- snapshots shrinking frontiers;
- entry-level reads, with fast sync through a map snapshot;
- a kick costing only the rotation;
- a user keeping its own messages after a kick;
- one-commit member wipe.

E is not clearly better until the frontier is settled.

## Corrections

1. e.md, e-evidence §3 and §6: `actor` is not verified. Add the sender display rule, and make it part of the history API.
2. e.md Costs and evidence §6: the frontier is commit IDs today, about 34 B per commit, never "10 B per aspect and device".
3. Remove the "occasional one-value snapshot". Change permissions §5.1 and `covered_here` to list commits before keep-at-least, and refuse or ignore snapshots on these aspects in the frontier.
4. Add device removal to the cost section, and the 8 MiB frontier limit (or raise it).
5. Per-year names bound re-merge only. Say so.
6. Tombstone: only on devices that applied the message. Decide whether markers are the default.
7. Add a purge item by (aspect, author), wider than "purge of invalid bodies".
8. Segments: add the roster re-apply rule and link handling. Drop the re-post.
9. crypto §7 says "actor directly above the author node", while code uses the header's actor. Align the spec.
10. e.md uses both `chat:msgs.0` and `chat:msgs:y2026.0`. Pick one.
11. History API must cover memory commits.
12. New issue, not E-only: wrap poisoning at hosts.

## Verdict

The crux holds: at honest nodes no non-admin can destroy another's body, by snapshot, purge, reset, `ts` or delete key. E2 over E1 stands, and so does the topology. But E is not ready to choose as written. Sender identity is unverified today, though one cheap rule fixes that. The real problem is structural: validity after any demotion needs one 32-byte ID per surviving message, because history is not carried by snapshots. That makes kicks, and especially routine device removal, O(all messages ever sent), caps them at about 2.5×10^5 commits today, and turns any snapshot into a way to hide a kicked member's past. Fix that first (the frontier rule now, per-session chains or an accepted cost next). If it is solved, E is the simpler and stronger design for rights and moderation, at the price of slow open and sync past about 10^5 messages and no compaction. If it is not, design C scales better and E only wins on moderator delete.
