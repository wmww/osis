# Durable writes in session form; per-session tables pruned; covered headers forgotten
> Summary: Design study (owner direction): every non-role commit writes under `Session(node, nonce)` (random per process start, memory-only counters), which removes item 193's restore gate and fixes issues/cloned-store.md; snapshot frontiers, receipt ranges and demotion frontiers list only sessions still traced in the aspect; nodes forget a content commit's header once all its held parts are gone as covered, expired or purged. Checks out with accepted residuals: a narrow atomic-apply partial-visibility race, per-session entries kept by sequence records, and forged-replay corners for equivocating or revoked writers (mostly pre-existing at new devices). Not built.
> Tags: engine, node, perm, crdt, spec, design

## Rules
1. **Dot forms.** Node form goes, and with it the `Node` source kind. A content commit (durable or memory) uses session form: dots `(Session(author, nonce), ctr)`. The nonce is drawn at random when the process starts and lives only in memory. Counters run per (aspect, session) from 1 and are kept only in memory. Role commits stay in commit form, so no later commit can void them. Link and recovery keys may use session form too, because a random nonce is safe on several devices. Commit form remains for role commits, snapshots and imports, through `Absorbed`.
2. **Traced session.** A session S is *traced* in an aspect at a node while S occurs in the node's state of that aspect, or in a body of it the node holds. "Occurs" means a stamp, an element or entry dot, an anchor or a sibling key that names S, value-less writes, tombstones and bare anchors included. For a snapshot, S occurs if it is in the fragment's `Sources`.
3. **Snapshot tables.** A snapshot's `Frontiers` lists exactly the sessions that occur in its fragment (ctr ≥ 1), and `Absorbed` lists exactly the commit sources that occur in it. Frontier-only sources go. Listing an untraced source is bad input, so "S absent" always means "S left no trace".
4. **Covered** (commits.md §5). A body of session S, or of commit C, is covered by snapshot Z when two things hold. First, joining it leaves Z's canonical bytes unchanged. Second, either Z's frontier for S reaches the body's counters (or `Absorbed` names C), or S (C) does not occur in Z. A snapshot body Z1 is covered by Z2 when it joins unchanged and Z2 reaches Z1 for every source both list.
5. **Atomic apply "dropped"** (commits.md §4, crdt.md §8). A missing part of commit c on aspect a counts as held if a held snapshot of a, stamped after c, either has a frontier for c's session that reaches the part's counters, or has no trace of that session at all.
6. **Receipt ranges** (`ix.ranges`, the `r/` record) are kept per (aspect, session) and forgotten once the session is no longer traced in the aspect.
7. **Demotion frontiers** (permissions.md §5.1). They are per (tid, ak, session of X), with the contiguous counter the demoter had received, over every session of X traced in that aspect at the demoter at T. Commit IDs are listed as today. Wire: one table of X's distinct sessions (16 B nonce each), then entries `[session index, ctr]`.
8. **Header forgetting** (replaces commits.md §5 "never headers"). A node forgets a content commit's header, meta, ranges and void mark once two things are true:
   - every part of it the node held is dropped as covered, expired, or purged;
   - node-sync tracks no entry of its blobs at any host.

   The value-less list (`v/`) and residues (`w/`) of expired or purged parts stay. They, not the header, strip late valued copies. Role commits are not forgotten: the timeline, certificates and epoch introductions read them. A thing's first commit is never forgotten either, because its `created.0` part is never covered. Memory commits follow the same rule (issues/eph-unify.md Header memory).
9. **Replays.** If a received commit's held parts are all covered by held snapshots, and its other parts are listed as in rule 5, it is dropped on arrival. This optional check saves re-indexing; join idempotence already keeps state correct.

## Check: late writes stay arrival-order independent
State is a join, so the question is only whether a forgotten table entry or header ever changes what a late write does. Take write W of session S arriving at node B after S was pruned from snapshot Z, or after W's header was forgotten:
- If Z's writer held W, then Z ⊒ W, so join(Z, W) = Z and W is dead on arrival.
- If not, W is a real write B lacked, and B joins it as usual.

B never needs to know which case it is in. Per construct:
- **Registers, enum cases, flags, `W`:** greatest stamp wins, so a late loser changes nothing.
- **Map removals:** the tombstone `(dot, -, R)` names the creator's session and the remover's. Both stay traced until a map reset prunes the tombstone. After that, a late creation is below the reset (pruned), unless it was concurrent and newer. In that case it was live in Z (traced, so not pruned) or Z's writer lacked it (a real write).
- **Set and bag elements:** the same as map removals.
- **Sequences:** records are never removed, so every inserting session stays traced for good (see Residuals). Deletes, undeletes and moves are flag max and top-2 positions, which are lattices.
- **Resets** (fragment and element): the effective reset is a max, and a superseded reset leaves nothing.
- **Value-less residues:** a value-less write in Z is a stamp, so it is traced. Late valued copies of expired or purged writes are stripped by the kept `v/` list. A new device takes T from the blob's header.
- **Undo:** writer-local. A forgotten later commit counts as in effect and not an undo, so undo does not step back past compacted history. That is the existing "dropped bodies cannot be undone", one level further.
- **Validity:** Z vouches for what it carries ("Snapshots vouch"). Forgotten commits' writes are either in Z or dead. If Z turns invalid, today's "counts as never received" path refetches what is still at hosts. A new device does the same.

## Readers and replacements
| Reader | Today | Without the entry or header | Replacement |
|---|---|---|---|
| Atomic apply `listed` (receipt.rs:208, apply/mod.rs:164) | Frontier reaches part | Waits forever for a deleted part | Rule 5 |
| Compaction `covered` (retention/mod.rs:1073, :1097) | Frontier and frontier ⊇ check, Node only | Never covers once S is pruned | Rule 4. Session check is missing today (Node only) |
| Receipts and demotion frontier (`received` :147, `Engine::frontier` :290; perm `Frontier::covers`) | Node ranges plus commit IDs | Durable session writes uncovered (invalid after revoke) | Rules 6 and 7. Perm `Frontier.writes` keyed by session |
| Receipts-only reads (permissions.md §5.3, receipt.rs:325) | By commit ID | Unchanged | None needed |
| Overlap void (atomic.rs:94, :507) | Both headers held | Undetected after forgetting | Residual (below) |
| Dedup by commit ID (`ingest_class`, node inbound `admits`) | Header held | Forgotten commit re-applies | Idempotent; rule 9; node-sync entry rows block re-fetch |
| Expiry T (`write_expiry`, strip_valueless, moves `excluded`) | Header | Late valued copy shows | `v/` list kept (rule 8) |
| Death dating, own-delta retention bounds | Header of held bodies | Already falls back to snapshot bodies (commits.md §5) | None |
| Purge judging (`purge_allowed`, `purge_one`, `drop_purged_snapshot`) | Named commit's header | Request naming a forgotten commit judged nowhere | As at a new device today. The purger resets live content and re-snapshots (commits.md §5), so only dead history was named |
| Undo "in effect" (undo/mod.rs:204, :311) | Headers of later commits | Undo commit forgotten | Forgotten counts as in effect (above) |
| Validity re-judge (`rejudge_once`, `Judge::part`) | Every meta | Nothing to judge | None. Writes live in snapshots |
| Imports: self-origin void (validity.rs:845), `import_one` | Origin header | Undetected | Malicious-creator residual; importer already imports from snapshots |
| Node-sync header reads (work.rs, pass/delete.rs, local.rs, inbound.rs) | Header per entry | Stuck deletes | Rule 8 waits for entries to go |
| Counters and restore (`node_form_ok`, `counters_sure`/`unsure`, `raise_counter`, examine adoption, `join_part` adoption, `MAX_NODE_COUNTER`, store COUNTER rows) | Item 193 | Not needed | Deleted |
| `moves.rs:73` (Node dots re-dotted), `flows/tied.rs:64` `TieSource` (Node, Commit), retention/mod.rs:1020 (scan from `Source::node(zeros)`), perm walk overlap `Dots::Node` | Node only | n/a | Generalize to Session; `validate.rs:146` drops "session form outside an ephemeral commit" |

## What goes
- Item 193's machinery (notes/node.md Counters), its commit-form window and `Absorbed` cost (~110 B per commit while unsure), and the 2^62 lying-frontier residue.
- issues/cloned-store.md: two live copies get different nonces.
- Node form, `Node` sources and per-aspect counter rows.
- Frontier-only sources, so per-writer entries for long-gone writers leave snapshots.
- Headers at old devices: about 690 B per overwriting commit, measured (notes/growth.md).

## Costs
- **Header:** +16 B nonce per commit (about 290 B now).
- **Foreign session in a delta or snapshot `Sources`:** 31 B instead of 15 B. Frontier entry about 3-5 B.
- **Plain register snapshot:** one traced session (the last writer's), about 40 B. Today it is one entry per node that ever wrote the aspect, plus 47 B per commit-form commit for good.
- **Text and lists:** 32 B per session whose inserted records survive, for good. Example: 1000 launches with inserts is 32 KB per text aspect, next to 3-4 B per deleted element of the same history. Creation runs no longer span commits of different launches: +1 run per session start, a few bytes.
- **Demotion frontier:** about 5 B per (aspect, traced session) plus 16 B per distinct session, against 10 B per aspect today. Plain data: about the same. Text: grows with inserting sessions.
- **Memory:** counters per (aspect, session) for aspects written since start.

## Requirements compromises (spec/requirements.md)
- **API "Atomic":** rule 5 also counts a missing part as dropped when a later snapshot was written concurrently by a node that had not yet received c. B can then show c without that part until the part arrives (it is under a label B syncs, so it does). Final state is unaffected. This is the same class as owner decision (a), a forged snapshot showing a commit partly. It needs the race of a concurrent snapshot plus out-of-order parts.
- **Cost "one entry per aspect it wrote":** becomes one per (aspect, traced session). For sequences that is every inserting session.
- **Permissions "judged by what the revoker had received":** becomes "received and still traced". A write of X with no trace at the demoter was dead there. It is not covered, so it stays gone even if its killer is later un-merged. Its effect is otherwise nil.

## Residuals and open points
- **Equivocation by a valid writer** (overlapping counters in one session): nodes still holding the first commit void both, while nodes that forgot it, and new devices today, count the second. This only matters where the first's writes are all dead. It is bounded by "authenticated malicious writers are bounded". Hardening: a write under a dot that a held valid snapshot's frontier reaches but that the snapshot does not carry counts for nothing (a no-op for honest writes, since Z ⊒ W).
- **Revoked writer forging into covered dots:** a demoted X writes c2 under counters its demotion covers in session S, after S lost every trace in snapshots. Nodes holding neither the original nor a snapshot listing S count c2. This is pre-existing at new devices today, where nothing voids it. Pruning widens it to old devices. Candidate fix, unchecked: snapshots keep frontier entries for sessions a held demotion covers (bounded by that demotion's own frontier), together with the hardening rule above. Optionally, a covered write counts only with `ts` ≤ the demotion's `ts`, which honest covered writes meet by HLC. Owner decision (a): close it (keep frontier entries for sessions a held demotion covers, so new devices are covered too); check the candidate fix's soundness before building. Its cost is a row in notes/growth.md.
- **Atomic apply with no snapshot at all:** a dead body dropped at hosts without a carrier (keep-at-most, commits.md §5) while another part of its commit is live elsewhere. Today's "dropped" rule also needs a snapshot here. Check whether this waits forever today.
- **Unexamined:** other per-node state a cloned store shares (HLC record, label steps, heartbeats) beyond counters.

## Plan sketch
Built after eph-unify step 3 (session-form commits through Core), since it shares the dot-form generalization (about 30 form-dependent sites, issues/eph-unify.md Step 2 Found):
1. Session form for durable content commits. Delete Node form and item 193.
2. Traced-session tables (rules 3-7), perm frontier keyed by session.
3. Header forgetting (rule 8, using `apply/free.rs` `unindex_commit` as the template).
4. Spec: crdt §2.1, §3.3, §8; commits §3-§5; permissions §5.1-§5.2; sync §7.
