# Durable writes in session form; per-session tables pruned; covered headers forgotten
> Summary: Design (Tess's direction, plan checked): every non-role content commit writes under `Session(node, nonce)` (random per process start, memory-only counters), which removed item 193's restore gate and fixed issues/cloned-store.md; demotion frontiers list commit IDs only, which closes Tess's decision (a) (a revoked writer forging into covered dots) with no snapshot pins; snapshot frontiers list only sessions still traced; nodes forget a content commit's header once its held parts are gone as covered, expired or purged. Six-step build plan below, each step mergeable alone; independent of eph-unify's swap. Steps 1, 2 and 5 built; steps 4 and 6 to build; step 3 not built (Tess/coordinator).
> Tags: engine, node, perm, crdt, spec, design

## Rules
1. **Dot forms.** Node form goes, and with it the `Node` source kind. A content commit (durable or memory) uses session form: dots `(Session(author, nonce), ctr)`. The nonce is drawn at random when the process starts and lives only in memory. Counters run per (aspect, session) from 1 and are kept only in memory. Role commits stay in commit form. Link and recovery keys may use session form too, because a random nonce is safe on several devices. Snapshots and imports have no own writes.
2. **Traced session.** A session S is *traced* in an aspect at a node while S occurs in the node's state of that aspect, or in a body of it the node holds. "Occurs" means a stamp, an element or entry dot, an anchor or a sibling key that names S, value-less writes, tombstones and bare anchors included. For a snapshot, S occurs if it is in the fragment's `Sources`.
3. **Snapshot tables.** A snapshot's `Frontiers` lists exactly the sessions that occur in its fragment, one entry each, ctr ≥ 0 (0: the writer applied none of the session's writes contiguously, yet one is in the fragment: a gap, e.g. a released part; without 0 entries "absent" could not stand for "no trace"), and `Absorbed` lists exactly the commit-form commits whose source occurs in it (an import has no own source and is in neither table). Frontier-only sources go. A frontier entry missing or untraced is bad input, so "S absent" always means "S left no trace". (`Absorbed` is not checked at decode: the ephemeral lane's covers list absorbed session-form commits by ID, which never occur as commit sources; its readers take an absent commit as untraced either way, so an extra entry changes nothing but bytes. Closes with eph-unify's swap, which retires that lane.)
4. **Covered** (commits.md §5). A body of session S, or of commit C, is covered by snapshot Z when two things hold. First, joining it leaves Z's canonical bytes unchanged. Second, either Z's frontier for S reaches the body's counters (or `Absorbed` names C), or S (C) does not occur in Z. A snapshot body Z1 is covered by Z2 when Z1 is stamped no later than Z2, it joins unchanged and Z2 reaches Z1 for every source both list. So covered-equal snapshots have equal `ts` (the higher ID goes); of others the older goes.
5. **Atomic apply "dropped"** (commits.md §4, crdt.md §8). A missing part of commit c on aspect a counts as held if the node holds a snapshot of a stamped after c, of any validity, signed by a possible holder of the role that snapshot needs (`Held::ever_holders`: a writer's compaction is honest and its body may be all that is left, anyone else's counts for nothing), whatever its frontier says: one reaching the part accounts for it, one with no trace of c's session says the part's writes are dead there or were never received, and one listing the session short of the part (a gap: it had a later write of the session but not this part) may have covered either kind (step 5 lets a snapshot cover an older one that lists sessions it holds nothing of), so it must stand in too, or a node that applied c under the older snapshot and a fresh node given only the newer one would differ (`sessions::pruned_sessions_converge_large` seed 154). A snapshot dropped as covered needs no record for this: its coverer is valid (so signed by a possible holder, and those only grow) and stamped no earlier, so it counts for all it did; one dropped otherwise stands in from its header (`Dropped::stands_in`), and if a coverer turns invalid it still counts. With this rule an older snapshot never covered a later one away (the bug: Z1, Z2 covered-equal around c, the higher-ID Z2 dropped at one node, c applied at another). Limits: a later snapshot holding less than an earlier one, or an invalid one, stays until a newer valid one covers it (its next compaction), one extra body per race. Frontiers serve covering only.
6. **Receipts.** No counter receipts. A node records only commit IDs it received without keeping them (receipts-only reads); a held commit's receipt time is its meta's. Snapshot frontiers no longer count as receipts.
7. **Demotion frontiers** (permissions.md §5.1) list commit IDs only, never counters. A session-form write is covered only when its commit's ID is listed. The demoter lists every commit of X it received by T that has a held part on an aspect in scope not covered by a held valid snapshot, plus what it lists today by ID (X's commit-form commits, imports, snapshots, receipts-only commits, its chain certificates). X's writes in commits it does not list stay only where a valid snapshot carries them (snapshots vouch, permissions.md §5.2). A demoter MAY compact first to shorten the list (step 3), never for a backdated revoke: the snapshot would vouch for writes received after T.
8. **Header forgetting** (replaces commits.md §5 "never headers"). A node forgets a content commit's header, meta, ranges and void mark once two things are true:
   - every part of it the node held is dropped as covered, expired, or purged;
   - node-sync tracks no entry of its blobs at any host.

   The value-less list (`v/`) and residues (`w/`) of expired or purged parts stay. They, not the header, strip late valued copies. Role commits are not forgotten: the timeline, certificates and epoch introductions read them. A thing's first commit is never forgotten either, because its `created.0` part is never covered. Nor is a lasting commit (spec/commits.md §5, built; `retention::lasting` is the check): a purged permanent delta's, its purge commit's. Memory commits follow the same rule (issues/eph-unify.md Header memory).
9. **Replays.** A forgotten commit that arrives again is indexed and joined again. Join idempotence keeps the state right; rule 7 keeps it invalid after a demotion that did not list it, and the snapshot that covered it vouches for its live writes. Node-sync's entry rows stop the node fetching it again. No drop-on-arrival check.

## Tess's decision (a): closed by rule 7
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
| Purge judging (`stands`, `purge_one`, `drop_purged_snapshot`) | Named commit's header | Request naming a forgotten commit judged nowhere | As at a new device today. The purger resets live content and re-snapshots (commits.md §5), so only dead history was named. A permanent delta's commit and its request are not forgotten (rule 8) |
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

## Latent: memory frontiers after a session is pruned
`compaction_snapshot`'s memory branch continues a session's range from the held valid snapshots' frontiers, because a memory commit's ranges go when it is forgotten. A session pruned from them (no write left) and writing again has lo > 1 with nothing to continue from, so the next snapshot lists it at 0, `unseen_by` holds, and its memory commits stop being covered. Test-only today (no production memory snapshots before eph-unify's swap), to fix at the swap. **Step 6 meets it durably**: forgetting a durable commit's header removes its `ix.ranges` entry, so a live session whose earlier commits were forgotten has the same gap at its next snapshot, and its bodies stop being covered and pile up. Step 6 needs a per-open memory floor per (aspect, session) (the counters are memory-only anyway: everything below the first still-known range was this node's or was forgotten as covered), or a frontier counted from the lowest known range.

## Requirements compromises (spec/requirements.md)
- **API "Atomic":** rule 5 as built (session-25) counts a missing part of c as held under any snapshot of its aspect stamped after c by a possible writer (admin for an admin-only aspect), whatever its frontier says, not only one reaching the part or holding nothing of c's session (the gap case, `pruned_sessions` seed 154: Z1 reached c, Z2 with no trace of c's session covered Z1, Z3 listing the session short of c covered Z2; a node given Z3 alone must not wait for a part that left hosts as covered while nodes that applied c under Z1 did not). So a snapshot written concurrently by a possible writer that had not yet received c, whether or not it holds c's session's other writes, lets B show c without that part until the part arrives (it is under a label B syncs, so it does; if its author never uploaded it, for good, where before c never applied anywhere but at its author). Final state is unaffected. Same class as Tess's decision (a) of round 13 (a forged snapshot showing a commit partly). A possible writer, removed or not, hiding a part with a host can do this, as it could on main by claiming a reaching frontier; anyone else cannot (`sessions::only_a_possible_writers_snapshot_counts_a_part_held_spec_commits_4`; on main anyone could). What widens is the honest race: any compaction concurrent with an in-flight multi-aspect commit, not only one where the session left no trace. No narrower rule is stable without frontier-only entries (the information Z2 drops is exactly what a per-session permanent entry would keep), which Tess ruled out. **Needs Tess's sign-off as a widening of the accepted Atomic compromise** (session-25 review).
- **Suspect flags settle under any later valid snapshot** (rule 5's rule; `receipt::settled`, Tess: simple and consistent over rare shapes). The flag only asks for a repair. The hole: the snapshot's author never received the body, so a node holding the body reads richer and no heartbeat says so. It closes when a writer holding it compacts (a body not covered stays uncovered there) or a copy reaches the flagged node (`takes_late`). A writer that applied the body, dropped it and then snapshotted had the same effect with frontiers; pending-expiry flags stay never dormant (their divergence is what the order oracle excuses). Left in heartbeats: pending-expiry entries, and flips on an aspect no writer compacts again; most recent first, so they cannot keep a newer flag out.
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

Step 1 is merged (item 219). Its review left two things for step 2:
- The covered filter also leaves out role commits, imports and snapshots, but rule 7 says they stay listed. A removed admin's rotation covered by a role snapshot then loses its record of which commit started the key epoch. That costs an extra safe rotation, not a security hole. Simplest fix: always list role commits. Square this with the lockout recovery (spec/permissions.md §3), which needs an admin to be able to leave a hostile rotation out.
- A commit whose held parts are covered is left out even if it also touches a thing the demoter does not hold. The spec says it should be listed. Main did the same before.
- Frontier size: 32 B per commit of the removed device. A roster snapshot past `MAX_LINKED_FRONTIERS` (64 MiB) is refused for good, so step 3 (compact before removing) or a cap rethink is needed.

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
   - Tess's choice (below): with or without this step.
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

**Steps 2 and 5 built** (branch session-25). Step 2: `Core::session` (one nonce per open, shared with the ephemeral lane's `Eph`); `write::commit_in` writes content commits in session form unless `Mutation::commit_form` (role commits, snapshots and imports commit form); `undo_in` session form; `Store::counter`/`reserve_counters` memory overlay rows only (`raise_counter`, `node_form_ok`, `MAX_NODE_COUNTER`, `counters_unsure`/`counters_sure`, `set_counters_unsure`, node-sync `counters_step` deleted); `validate`: node form bad input, session form only on content commits; `writer_ctx(form, kind, ...)`; schema `source` gains `2 session(blob)` (31 bytes), perm `TieSource::Session`. Step 5: `osis_crdt::sources_of` (the collecting pass) and `Frontiers::retain` give the writer the traced sources; the encoder emits one entry per Node/Session source of the table (0 where the writer has none) and the decoder requires exactly that (a 0 entry decodes as none); `unseen_by` takes an absent session as untraced (an entry of 0 is a gap: not covered), `receipt::listed` is any later snapshot of the aspect (rule 5 as amended above), `receipt::settled` (suspect flags) any later snapshot valid here; the snapshot ⊇ check runs over sessions both list and no longer reads `Absorbed`; a delta with an expiry is never covered (was: covered once dropped, found by `order::new_device_alike_large` seed 125). Left for step 4: the `Form::Node`/`Source::Node` variants and their arms (`Frontiers::nodes`, `Frontiers::of_nodes`, perm `TieSource::Node`, schema `source` case 0, index/records/pages encodings, crdt tests and vectors writing under node sources, the crdt-model's `Source::Node`). Measured (osis-node `retention::frontier_bytes_per_launch_probe`, `#[ignore]`): a register written once per launch over 1000 launches lists one session in its snapshot frontier (notes/growth.md row 5). Tests: `sessions::snapshot_lists_only_traced_sessions_spec_crdt_8` (one entry, earlier launches' bodies and an earlier snapshot covered), `sessions::untraced_session_part_counts_held_spec_commits_4`, `sessions::untraced_frontier_entry_is_bad_input_spec_crdt_8`, `sessions::pruned_sessions_converge_spec_crdt_8` (the step-5 differential: random writes by two writers across restarts, compacted at random points; a fresh node from what a writer still holds reads alike, and so does every node after every original body is replayed; `_large` twin on `OSIS_SESSIONS_START`/`_SEEDS`), `crash::two_live_copies_of_one_store_converge_spec_crdt_2_1`, osis `sync::restored_store_writes_at_once_spec_crdt_2_1`; deleted `crash::restored_counter_from_snapshot_frontier_*`, `validity::lying_frontier_leaves_writes_*`. Also in the branch: `Peer::restart` mixes an open counter into the test rng seed (a reseeded open drew the same nonce and voided its own earlier commits); node-sync's `redeliver` judges every entry of a named commit before skipping those whose slots a true copy brought (a junk copy sorting after the true one stayed unmarked).

**Steps 2 and 5 build together** (coordinator, after the session-2 worker stopped before coding). Session form alone makes every snapshot frontier carry one entry per session that ever wrote the aspect: frontier-only sources, which Tess rules out ("nothing grows permanently by number of app launches/sessions"). Pruning needs step 5's no-trace escapes, and step 5 alone breaks item 193's restore gate, which step 2 deletes. So both go in one branch, an exception to one-intricate-change-per-area. Also in step 2: the tie source gains a `Session` variant, and node form is refused, so every `Form::Node` test commit and the commit vector subjects change.

## Tess's decisions (round 13)
- Rule 7 in place of the earlier candidate for decision (a): accepted ("seems fine"), with its 32 B per uncompacted commit and the double-removal residual.
- Step 3 (compact before an explicit demotion): left to the coordinator, who chose **no** for now: nothing blinks out, and frontiers stay bounded by compaction cadence. Revisit if demotion frontiers measure large.
- atomic-wait-carrierless-drop (built): count a carrierless-dropped dead part as held, accepted ("fine").
- Tess earlier: "if it all checks out feel free to implement": build steps 1, 2, 4, 5, 6 in order.

## Frontier study
notes/frontier-study.md: rule 7 becomes "lists every received commit of X in scope that is not droppable now" (covered by a snapshot received by T, past keep-at-least, purgeable), with a head per (aspect, device) instead of IDs for aspects whose deltas are all permanent (keep forever, no keep-at-most, no expiry), followed through per-session predecessor links in X's own headers (needs step 2). Fixes issues/frontier-clobbers-history.md, dissolves both step-2 carry-overs (role commits follow the same rule; a commit with a part this node does not hold is listed). Rule 8 gains: a permanent delta's header is never forgotten, its purge residue stays must-hold. Step 3 now also bounds kick cost on compacting aspects. Chains across all aspects of a session are rejected (unwalkable across labels).
