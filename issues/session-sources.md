# Durable writes in session form; per-session tables pruned; covered headers forgotten
> Summary: Design (owner direction, plan checked): every non-role content commit writes under `Session(node, nonce)` (random per process start, memory-only counters), which removes item 193's restore gate and fixes issues/cloned-store.md; demotion frontiers list commit IDs only, which closes owner decision (a) (a revoked writer forging into covered dots) with no snapshot pins; snapshot frontiers list only sessions still traced; nodes forget a content commit's header once its held parts are gone as covered, expired or purged. Six-step build plan below, each step mergeable alone; independent of eph-unify's swap. Step 1 built (rules 6, 7); steps 2, 4, 5, 6 to build; step 3 not built (owner/coordinator).
> Tags: engine, node, perm, crdt, spec, design

## Rules
1. **Dot forms.** Node form goes, and with it the `Node` source kind. A content commit (durable or memory) uses session form: dots `(Session(author, nonce), ctr)`. The nonce is drawn at random when the process starts and lives only in memory. Counters run per (aspect, session) from 1 and are kept only in memory. Role commits stay in commit form. Link and recovery keys may use session form too, because a random nonce is safe on several devices. Snapshots and imports have no own writes.
2. **Traced session.** A session S is *traced* in an aspect at a node while S occurs in the node's state of that aspect, or in a body of it the node holds. "Occurs" means a stamp, an element or entry dot, an anchor or a sibling key that names S, value-less writes, tombstones and bare anchors included. For a snapshot, S occurs if it is in the fragment's `Sources`.
3. **Snapshot tables.** A snapshot's `Frontiers` lists exactly the sessions that occur in its fragment (ctr ≥ 1), and `Absorbed` lists exactly the commit sources that occur in it. Frontier-only sources go. Listing an untraced source is bad input, so "S absent" always means "S left no trace".
4. **Covered** (commits.md §5). A body of session S, or of commit C, is covered by snapshot Z when two things hold. First, joining it leaves Z's canonical bytes unchanged. Second, either Z's frontier for S reaches the body's counters (or `Absorbed` names C), or S (C) does not occur in Z. A snapshot body Z1 is covered by Z2 when it joins unchanged and Z2 reaches Z1 for every source both list.
5. **Atomic apply "dropped"** (commits.md §4, crdt.md §8). A missing part of commit c on aspect a counts as held if a held snapshot of a, stamped after c, either has a frontier for c's session that reaches the part's counters, or has no trace of that session at all.
6. **Receipts.** No counter receipts. A node records only commit IDs it received without keeping them (receipts-only reads); a held commit's receipt time is its meta's. Snapshot frontiers no longer count as receipts.
7. **Demotion frontiers** (permissions.md §5.1) list commit IDs only, never counters. A session-form write is covered only when its commit's ID is listed. The demoter lists every commit of X it received by T that has a held part on an aspect in scope not covered by a held valid snapshot, plus what it lists today by ID (X's commit-form commits, imports, snapshots, receipts-only commits, its chain certificates). X's writes in commits it does not list stay only where a valid snapshot carries them (snapshots vouch, permissions.md §5.2). A demoter MAY compact first to shorten the list (step 3), never for a backdated revoke: the snapshot would vouch for writes received after T.
8. **Header forgetting** (replaces commits.md §5 "never headers"). A node forgets a content commit's header, meta, ranges and void mark once two things are true:
   - every part of it the node held is dropped as covered, expired, or purged;
   - node-sync tracks no entry of its blobs at any host.

   The value-less list (`v/`) and residues (`w/`) of expired or purged parts stay. They, not the header, strip late valued copies. Role commits are not forgotten: the timeline, certificates and epoch introductions read them. A thing's first commit is never forgotten either, because its `created.0` part is never covered. Memory commits follow the same rule (issues/eph-unify.md Header memory).
9. **Replays.** A forgotten commit that arrives again is indexed and joined again. Join idempotence keeps the state right; rule 7 keeps it invalid after a demotion that did not list it, and the snapshot that covered it vouches for its live writes. Node-sync's entry rows stop the node fetching it again. No drop-on-arrival check.

## Owner decision (a): closed by rule 7
The residual: a demoted X writes c2 under counters its demotion D covers in session S, after S lost every trace in snapshots. Nodes holding neither the original c1 nor a snapshot listing S count c2.

**The candidate fix fails.** The candidate was: snapshots keep entries for sessions a held demotion covers, plus the hardening rule ("a write under a dot a held valid snapshot's frontier reaches but the snapshot does not carry counts for nothing"), optionally `ts ≤ T`.
- If the kept entry takes D's counter, the snapshot claims writes its writer never applied. The hardening rule then deletes honest live writes the writer lacked. The entry would have to be the writer's own applied counter.
- A writer that has not yet received D prunes S like any untraced session. Under rule 4 its snapshot covers the older snapshots that traced S, so those drop at hosts. Nodes that get D later have forgotten S's receipts (rule 6), so nobody can add the entry back. New devices then count c2. This is an honest race, but X can see the result and exploit it.
- Closing that race takes five rules:
  - sticky pins, set by a snapshot written with D;
  - a covering rule that keeps pins;
  - the hardening rule with a bound of `ts ≤` the snapshot's ts. Without the bound, a lying frontier mutes a live session's future writes for 5 bytes;
  - `ts ≤ T` for covered writes, or a forgery stamped after the pinning snapshot escapes;
  - a demoter frontier counted from applied writes, not received ones (received-but-pending writes are not in the pinning snapshot).

**Replacement: rule 7, no counter coverage for sessions.** Ephemeral writes are already treated this way ("a demotion's frontier lists no ephemeral commit").
- Attack, demoted X: c2 has a fresh commit ID that no frontier lists. At every node holding D, c2 is invalid whatever counters it reuses or whatever its `ts` is.
- Replays of c1 after its header was forgotten: c1 was not listed (covered), so it is invalid. Its live writes come from the snapshot that covered it (vouched); its dead writes stay dead.
- Equivocation by X before D: an unlisted copy is invalid. A copy D lists is the one A received.
- Colluding remaining writer: it can write the content itself (out of scope, as today).
- Snapshots by X before D: X's snapshots are listed by ID as today. A valid one vouches for what it carries, which X could write anyway while it held write.
- Forks and clones: every copy draws its own nonce, so no two copies share counters.
- A node that has not yet received D counts c2 as a valid writer's write until D arrives, like any write by a removed writer. An honest compactor that snapshots c2 before it learns of D keeps it for good (spec/requirements.md: "except those another writer compacted before it learned of the revocation, which stay").
- New devices: they hold D (role commits) and judge c2 invalid.
- Arrival order: rule 7 is a function of the held set, so a node getting D after c2 and one getting it before end up alike.
- Compaction pruning and header forgetting no longer matter here: no demotion reads snapshot frontiers or counters.
- Cost: 32 B per listed commit, against 10 B per (aspect, node) today. The list is X's commits with uncovered held parts in scope: the tail since the last snapshot. A demoter that compacts first (rule 7) lists about none; a backdated revoke lists the tail. No pins, no permanent per-session entries: notes/growth.md's "demoted writers' session entries" row goes.
- Residual: say A's frontier leaves out c because a valid snapshot Z by Y covered it, and Y is later removed by a demotion whose demoter had not received Z. Then Z turns invalid and c's live writes are lost even where c's body is still held. With counters, D covered c. This needs a second removal plus a missed snapshot. A demoter that lists every commit with a held part (no covered filter) avoids it at frontier cost. That is a local policy and changes no wire format.
- Not needed any more: the hardening rule, pins, `ts ≤ T`, and per-session demotion entries.

## Check: late writes stay arrival-order independent
State is a join, so the question is only whether a forgotten table entry or header ever changes what a late write does. Take write W of session S arriving at node B after S was pruned from snapshot Z, or after W's header was forgotten:
- If Z's writer held W, then Z ⊒ W, so join(Z, W) = Z and W is dead on arrival.
- If not, W is a real write B lacked, and B joins it as usual.

B never needs to know which case it is in. Per construct:
- **Registers, enum cases, flags, `W`:** greatest stamp wins, so a late loser changes nothing.
- **Map removals:** the tombstone `(dot, -, R)` names the creator's session and the remover's. Both stay traced until a map reset prunes the tombstone. After that, a late creation is below the reset (pruned), unless it was concurrent and newer. In that case it was live in Z (traced, so not pruned) or Z's writer lacked it (a real write).
- **Set and bag elements:** the same as map removals.
- **Sequences:** records are never removed, so every inserting session stays traced for good (see Costs). Deletes, undeletes and moves are flag max and top-2 positions, which are lattices.
- **Resets** (fragment and element): the effective reset is a max, and a superseded reset leaves nothing.
- **Value-less residues:** a value-less write in Z is a stamp, so it is traced. Late valued copies of expired or purged writes are stripped by the kept `v/` list. A new device takes T from the blob's header.
- **Undo:** writer-local. A forgotten later commit counts as in effect and not an undo, so undo does not step back past compacted history. That is the existing "dropped bodies cannot be undone", one level further.
- **Validity:** Z vouches for what it carries ("Snapshots vouch"). Forgotten commits' writes are either in Z or dead. If Z turns invalid, today's "counts as never received" path refetches what is still at hosts. A new device does the same.

## Readers and replacements
| Reader | Today | Without the entry or header | Replacement |
|---|---|---|---|
| Atomic apply `listed` (receipt.rs:208, apply/mod.rs:164) | Frontier reaches part | Waits forever for a deleted part | Rule 5. Pre-existing gap without any snapshot: issues/atomic-wait-no-later-commit.md |
| Compaction `covered` (retention/mod.rs:1087, :1097) | Frontier and frontier ⊇ check, Node only | Never covers once S is pruned | Rule 4. Session check is missing today (Node only) |
| Receipts and demotion frontier (`received` :147, `Engine::frontier` :290; perm `Frontier::covers`) | Node ranges plus commit IDs | n/a | Rules 6 and 7: IDs only; `Receipt.sources`, `received`'s snapshot claims, perm `Frontier.writes` go |
| Receipts-only reads (permissions.md §5.3, receipt.rs:252) | By commit ID | Unchanged | None needed |
| Overlap void (atomic.rs:94, :507) | Both headers held | Undetected after forgetting | Equivocation residual (below) |
| Dedup by commit ID (`ingest_class`, node inbound `admits`) | Header held | Forgotten commit re-applies | Rule 9 |
| Expiry T (`write_expiry`, strip_valueless, moves `excluded`) | Header | Late valued copy shows | `v/` list kept (rule 8) |
| Death dating, own-delta retention bounds | Header of held bodies | Already falls back to snapshot bodies (commits.md §5) | None |
| Purge judging (`purge_allowed`, `purge_one`, `drop_purged_snapshot`) | Named commit's header | Request naming a forgotten commit judged nowhere | As at a new device today. The purger resets live content and re-snapshots (commits.md §5), so only dead history was named |
| Undo "in effect" (undo/mod.rs:204, :311) | Headers of later commits | Undo commit forgotten | Forgotten counts as in effect (above) |
| Validity re-judge (`rejudge_once`, `Judge::part`) | Every meta | Nothing to judge | None. Writes live in snapshots |
| Imports: self-origin void (validity.rs:845), `import_one` | Origin header | Undetected | Malicious-creator residual; importer already imports from snapshots |
| Node-sync header reads (work.rs, pass/delete.rs, local.rs, inbound.rs) | Header per entry | Stuck deletes | Rule 8 waits for entries to go |
| Counters and restore (`node_form_ok`, `counters_sure`/`unsure`, `raise_counter`, examine adoption, `join_part` adoption, `MAX_NODE_COUNTER`, store COUNTER rows) | Item 193 | Not needed | Deleted (step 2) |
| `moves.rs:73` (Node dots re-dotted), `flows/tied.rs` `TieSource` (Node, Commit), retention/mod.rs:1020 (scan from `Source::node(zeros)`), perm walk overlap `Dots::Node` | Node only | n/a | Generalize to Session (step 2), delete Node (step 4) |

## What goes
- Item 193's machinery (notes/node.md Counters), its commit-form window and `Absorbed` cost (~110 B per commit while unsure), and the 2^62 lying-frontier residue.
- issues/cloned-store.md: two live copies get different nonces.
- Node form, `Node` sources, per-aspect counter rows.
- Counter receipts (`r/` ranges per minute bucket) and per-(aspect, node) demotion entries; perm `Frontier.writes`.
- Frontier-only sources, so per-writer entries for long-gone writers leave snapshots.
- Headers at old devices: about 690 B per overwriting commit, measured (notes/growth.md).

## Costs
- **Header:** +16 B nonce per commit (about 290 B now; budget test ≤ 330 B, check in step 2).
- **Foreign session in a delta or snapshot `Sources`:** 31 B instead of 15 B. Frontier entry about 3-5 B.
- **Plain register snapshot:** one traced session (the last writer's), about 40 B. Today it is one entry per node that ever wrote the aspect, plus 47 B per commit-form commit for good.
- **Text and lists:** 32 B per session whose inserted records survive, for good. Example: 1000 launches with inserts is 32 KB per text aspect, next to 3-4 B per deleted element of the same history. Creation runs no longer span commits of different launches: +1 run per session start, a few bytes.
- **Demotion frontier:** 32 B per listed commit (rule 7), against 10 B per aspect today. About none when the demoter compacts first.
- **Memory:** counters per (aspect, session) for aspects written since start.

## Requirements compromises (spec/requirements.md)
- **API "Atomic":** rule 5 also counts a missing part as dropped when a later snapshot was written concurrently by a node that had not yet received c. B can then show c without that part until the part arrives (it is under a label B syncs, so it does). Final state is unaffected. This is the same class as owner decision (a) of round 13, a forged snapshot showing a commit partly. It needs the race of a concurrent snapshot plus out-of-order parts.
- **Cost "one entry per aspect it wrote":** a snapshot holds one entry per (aspect, traced session). For sequences that is every inserting session.
- **Permissions "judged by what the revoker had received":** a received write that a held valid snapshot shows dead is not covered. It stays gone even if its killer is later un-merged, which can only happen where that snapshot is invalid. Also the double-removal residual under decision (a) above.
- **Transient after a demotion with compaction first (step 3):** a node that holds X's original bodies and gets D before the demoter's snapshot un-merges X's writes until the snapshot arrives. Listing IDs instead (no compaction) has no such window.

## Open points, resolved
- **Equivocation by a valid writer** (overlapping counters in one session): nodes holding the first commit void both. Nodes that forgot it, and new devices today, count the second. Where the first's writes are live, a held valid snapshot carries them and the misstatement rule (permissions.md §5.2) voids the second's writes under those dots. So only a still-valid writer whose first commit's writes are all dead can split nodes. It could write the second commit with fresh counters anyway. Not hardened: the hardening rule only narrows this (it stops once S is pruned), and rule 7 already removes the demoted-writer case. Accepted under "authenticated malicious writers are bounded". The overlap void stays: one dot names one write.
- **Atomic apply with no snapshot at all:** yes, a commit can wait forever today. A body with no live write under keep at most is deleted at hosts with no carrier (commits.md §5), so a node that later gets its commit's other body never gets this one, and no snapshot lists it (`waits_for_deltas`). Filed as issues/atomic-wait-carrierless-drop.md with a repro sketch. Pre-existing, independent of this design.
- **Other per-node state a cloned store shares**, checked:
  - HLC record: both copies continue from one last `ts`. Equal `ts` across copies is harmless, because stamps break ties by dot and the nonces differ.
  - Label steps and rotations: two copies act like two admin devices. A host takes one child of its head; concurrent rotations fork as spec'd.
  - Heartbeats (`seen.0`): ordinary content writes in session form, so the newest wins.
  - Undo buffers: each copy undoes under its own session.
  - Own deposits: same bytes, so the same blob ID.
  - Uploads of a shared commit: duplicate bodies at hosts. Readers dedup by commit ID, and covered drops remove them.
  - Signing: Ed25519 is deterministic. Blob keys, blinds and delete-key nonce salts are random per encryption.
  - Only the transport identity is left. Both copies answer for one dialable key (`reach.0`), and LAN receivers keep the first source address they verified. That costs connectivity, not correctness: noted in issues/cloned-store.md.

## Build order
eph-unify step 3 is not a prerequisite. The dot-form generalization this design needs is already on main from eph-unify 3a: `Form::Session` with `own_source`/`counted`, `Owned::Range { src }`, and `Core::ranges`/`Receipt::sources` keyed by own source. What eph-unify still lacks is the swap of local and received memory commits (Left item 2), and none of these steps touches it:
- Durable session commits and memory session commits share one nonce. Their aspects are disjoint (class by key), so their counters never meet.
- The swap later gets traced tables and header forgetting for memory commits for free. eph-unify Left item 4 is built here, for both classes.
- Rule 7 matches eph-unify's model ("demotion frontiers list no session source").

Merging this with the swap would put two intricate changes in one branch (notes/coordination.md: one intricate change per area at a time). Build these steps first.

## Plan
Each step merges alone, passes the gate, and updates the spec sections it changes. The verification lists targeted differentials; seed breadth comes from the periodic runs.

1. **Demotion frontiers by commit ID** (rules 6, 7). **Built** (branch session-1): perm `Frontier { commits }`, `covers(commit)`, `delta_valid(at, thing, required)` (`Dots` gone); schema `frontier = struct { 0 commits }`; `Engine::frontier` lists the demoted node's held durable commits received by `as_of` on scope aspects unless `receipt::covered_here` (part dropped as covered, or held and `retention::covered` by a held snapshot stamped after it), plus the `r/` receipts-only IDs; `Receipt` is the receipts-only record alone; `Core::receipts_only` gone (everything is by ID); waits wake on a snapshot's applied parts (`atomic::wake_listed`, what `record` used to do). Coverers count only if received by the frontier's cutoff (review: a backdated revoke otherwise left out a write its demoted author's own later snapshot covered, and that snapshot, unlisted, vouched for nothing; `validity::backdated_frontier_lists_write_covered_after_cut_spec_perm_5_1`); judgment vectors keep main's verdicts (the order harness's removals are backdated, so rules.vec seed 21187's part, covered by A's snapshot written after the cut, stays listed and valid). Tests: `validity::revoked_writer_forging_into_covered_counters_spec_perm_5_1`, `frontier_lists_uncovered_snapshot_vouches_covered_spec_perm_5_1`, `backdated_frontier_lists_by_cutoff_spec_perm_5_1`, `order::new_device_alike_spec_permissions_5_1` (and `_large`). The plan as written:
   - perm: `Frontier` is `commits` only (`types.rs`, `cache.rs` encoding, schema `core_types::Frontier` field 0 goes, ledger `Tenure.frontier`); `Frontier::covers` checks the ID alone.
   - engine `apply/receipt.rs`:
     - `Engine::frontier` lists X's commits received by `as_of` (meta `received`) with a held part on a scope aspect that `retention::covered` does not report covered by a held valid snapshot, plus today's ID lists;
     - `Receipt.sources`, `add`, `contiguous`, `GRANULARITY_MS`, `received`'s claim logic and `record` go; the `r/` record keeps receipts-only IDs (`record_header`);
     - callers: `flows/edges.rs:413`, `flows/roster.rs`, `apply/validity.rs` `frontier_of`.
   - Models: `core/test/roles-model` (content.rs, single.rs frontiers) and TLA roles if they model counters.
   - Spec: permissions.md §5.1 Frontier, §5.2 (covered by ID; the "revoked actor cannot reuse a covered dot" line goes, overlap void stays for one dot = one write), §6 ledger; crdt.md §8 (frontiers are not receipts); data-model.md frontier type; wire.md frontier. notes/permissions.md Revocation (sizes, receipts, dot reuse).
   - Tests:
     - new: the (a) attack (X forges under counters D's frontier would have covered; invalid at a fresh node holding D and a snapshot, fails on main);
     - new: X's received uncompacted live write stays (listed), and its compacted one stays (vouched);
     - new: a backdated revoke lists only commits received by its cutoff;
     - rework: `contiguous_as_of_spec_5_1`, `apply/tests_order.rs`, `tests_linked.rs`, `tests_paged.rs` frontier asserts.
   - Verification: perm tier 2 (`differential:: roster:: queries:: incremental::`); order `arrival_order_alike`. New differential: random histories with a demotion, comparing a node that holds every body with a fresh node that holds only D, the snapshots and the uncovered bodies (the new-device equivalence decision (a) is about).
2. **Session form for durable content; item 193 deleted.**
   - commit `validate.rs`: session form allowed for any content commit; a role or roster-snapshot commit in session form is bad input (replaces the node-form check); node form refused.
   - Plans use `Form::Session(eph.session().nonce)`; imports and snapshots `Form::Commit` (`moves.rs:197,324`, `retention/mod.rs:1048`, `write.rs:82`); undo always session (`undo/mod.rs:137`).
   - Counters: `Store::counter`/`set_counter` always write overlay rows (memory, rolled back with an aborted transaction, gone at restart). A gap would stop snapshot frontiers and drops.
   - Deleted: `node_form_ok`, `MAX_NODE_COUNTER`, `Core::counters_unsure`/`counters_sure`, `Engine::set_counters_unsure` (and its node callers `sync/deliver.rs:426`, `sync/mod.rs:524`, `counters_step`), `Store::raise_counter` and its two callers (`apply/mod.rs:218`, `atomic.rs:291`).
   - Generalized to session dots: `retention/mod.rs:1087` (`by_frontier` from `form.counted()`, frontier per session), retention frontier scan (:1020), `moves.rs:73`, `flows/tied.rs`.
   - Spec: crdt.md §2.1 (Node paragraph and restore gate go; Session for every content commit), commits.md §3, §4, wire.md §4 form values, data-model.md if it names node form. notes/node.md Counters rewritten.
   - Tests:
     - rewrite: osis `sync::restored_store_reuses_no_counter_spec_crdt_2_1` (a restored copy writes at once, nothing voided);
     - new: two live copies write concurrently and converge with no `OverlappingCounters` diagnostic (then delete issues/cloned-store.md, keeping its transport note in notes/node.md);
     - delete: node `crash::restored_counter_from_snapshot_frontier_spec_crdt_2_1`, `validity::lying_frontier_leaves_writes_spec_crdt_2_1`;
     - keep: sim `restore_backup` (its reuse check must stay silent).
   - Verification: walks `open_equals_rebuild` (default and forged variants), order exhaustive, sim `restore_backup`, bench budgets (header ≤ 330 B), the growth probe (COUNTER rows gone).
3. **Demoter compacts first** (rule 7's MAY, local policy). In the revoke flow (`flows/edges.rs` before `frontier`), when `as_of` is now: `compaction_snapshot` for each scope aspect where this node holds an uncovered part of a demoted node, in the same transaction as the demotion.
   - Test: the frontier lists nothing for those aspects, X's live writes reach a fresh node through the snapshot, and a backdated revoke compacts nothing.
   - Owner choice (below): with or without this step.
4. **`Node` source kind deleted.** Mechanical; no behavior change.
   - crdt `stamp.rs`, `wire.rs`, `codec.rs`, `Frontiers { nodes }`, `pages.rs`, fuzz and test utils; crdt-model `Source::Node`; perm `Dots::Node` and walk overlap; commit `Form::Node`; engine `index.rs` meta form byte.
   - Spec: crdt.md §2.1-§2.2 source order, wire grammar.
   - Verification: tier 1 and the crdt random set at one offset.
5. **Traced tables** (rules 3-5):
   - snapshot writers list only occurring sources (`retention/mod.rs` frontier build, `Absorbed`);
   - decode refuses an untraced listed source;
   - `covered` and `receipt::listed` take the no-trace escape;
   - the snapshot ⊇ check is over sources both list.
   - Spec: crdt.md §3.3 rule 1, §8; commits.md §4, §5.
   - Verification: walks with compaction (covered drops on), `validity::listed_part_alike_in_any_order_*`. New differential: random histories compacted at random points, so sessions get pruned; a fresh node from snapshots must equal a node with full history, then all old commits replayed into both.
6. **Header forgetting** (rule 8), both classes, using `apply/free.rs` `unindex_commit`. Node-sync reports when a commit's entries are gone. Kept: `v/`, `w/`, role commits, first commits.
   - Test: like `free_equals_never_indexed`, forgetting equals never having held the commit, beyond the kept rows.
   - Differential: a node that forgot vs one that kept, after replaying every forgotten commit, reads the same.
   - Re-measure the growth probe (the 690 B per overwrite row).
   - Spec: commits.md §5 "never headers" replaced; sync.md §7.

Item 193 code: deleted in step 2, except `Form::Node`/`Source::Node` arms (step 4).

## Owner decisions (round 13)
- Rule 7 in place of the earlier candidate for decision (a): accepted ("seems fine"), with its 32 B per uncompacted commit and the double-removal residual.
- Step 3 (compact before an explicit demotion): left to the coordinator, who chose **no** for now: nothing blinks out, and frontiers stay bounded by compaction cadence. Revisit if demotion frontiers measure large.
- atomic-wait-carrierless-drop (built): count a carrierless-dropped dead part as held, accepted ("fine").
- Owner earlier: "if it all checks out feel free to implement": build steps 1, 2, 4, 5, 6 in order.
