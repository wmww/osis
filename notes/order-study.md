# Order-independence meets retention: converging or endless?

> Summary: study of the arrival-order bug stream: reads alike is converging, agreement on which bodies and death dates nodes hold is endless and never required. Recommends narrowing the oracle and commits.md §5, a stated expiry exception, one nesting rule. Done: the oracle and commits.md §5 are narrowed, spec/requirements.md states the flip-after-drop and expiry-before-apply exceptions; question 6 of notes/questions-for-tess.md is open.

Read-only study for the coordinator. Figures from `git log` on main at 71d0b293 (2026-11-03). Project age six weeks (first commit f67de08c, 2026-09-22); the node-level order harness is twelve days old (a94345bf, 2026-10-23).

## 1. What is actually required

**spec/requirements.md** (Decentralization, lines 15-16; Deletion, line 58; Data model, line 69; Permissions, lines 109, 115):
- User-visible: "Convergence under any delivery order"; "Nodes holding the same bodies read alike; a node missing a body reads as if it never had it until it arrives"; a keep-at-most drop "stays dropped only at nodes that cannot get it back"; "Expired and purged content never returns"; purge prompt, no bin, no fingerprint.
- Also stated: "a node's state and its judgment of every write are functions of the data it holds, never of arrival order". "State" is the only word that could be read as internal agreement; nothing in requirements names which body rows are held, when a death is dated, or index tables.
- Stated exceptions so far: commits across things (32677c5b, Nov 2), roster snapshot (01d5db6c, Nov 3), the Atomic "part still to arrive under a later snapshot" (e53f8429, Nov 2). The "same bodies read alike" sentence itself is three days old (c4438654, Nov 1, from notes/convergence-study.md).

**spec/commits.md §4-5 add** (all internal unless noted): which parts of a commit apply is a function of what is held (§4, one 712-word bullet); per-body first/last death dating with six re-dating sub-cases and the admission "nodes holding the same commits may hold different dates" (§5 line 58, 385 words); bounds "may differ between nodes until they hold the same commits"; a dropped body "counts as never received" and rejoins (R1); carrier-only snapshots; stand-ins for dropped snapshots; value-less held waiting parts; §5 line 61 (696 words) on keep at most. **spec/crdt.md** adds: un-merge is a function of the held set "but for a body the node dropped for its keep bounds or ... purged values" (§4.6), value-less residues and key-erased map records (§4.7), death of a write (§4.8).

**What the oracle compares** (core/node/tests/it/order.rs `alike`, 1559-1655; notes/testing.md line 110): reads, states, rosters, pending sets, perm timelines (user-visible or close to it), **and** every body's held flag (`facts`), the persisted index digest a day later (`bounded_held`, dropped snapshots, carried, by_aspect), and deaths against a keep-everything oracle (`dating`, 1278-1328). The last three are internal agreement the requirements never ask for. To keep them exact the harness now carries eight tolerance families (`expired_pending`, `parted`, `orphan`/`orphaned`, `bounded_held` counting, `approx`, `drop_flips`, `both_dropped_flips`, `purge_flips`), 49 excuse/limit mentions, each citing a seed.

## 2. The trend

Counts of issues whose file name matches the retention/order vocabulary (order, alike, seed, death, keep, at-most, expir, purge, snapshot, undo, cover, drop, body, valid, unmerge, pending, residue, carri, eph-, parts-):

| | W42 | W43 | W44 | W45 (2 days) |
|---|---|---|---|---|
| created | 7 | 28 | 107 | 84 |
| deleted | 7 | 26 | 97 | 62 |

Per day, Oct 28 to Nov 3: created 12, 29, 31, 13, 14, 59, 26; deleted 13, 27, 28, 13, 12, 41, 21. 193 such issues closed by 164 commits; 21 named open, all 21 filed Nov 1-3. The arrival rate is rising, but so is everything (745 commits in the three days of November, 2390 in October); fixed-to-found stays near 1:1, so the open set is a conveyor, not a pile.

Are they the same root causes? Mostly no at the symptom level, yes at the class level. The periodic checks' bug log (notes/mvp-progress.md lines 308-656) says the default `order::` ranges at 300 seeds have been clean in 6 of the last 8 runs ("fifth clean run", "no new product bug"). The new issues come when the generator's reach grows or a feature lands: clock mode (1f4f01bd, Nov 3) found applied-by-part-before-expiry; `new_device_alike_large` (Nov 1) found seed 883125; `Step::PurgeAuthor` mixing found wide-purge-order; forcing at most 0 on every aspect via `Require` found at-most-map-snapshot-drop; session-sources, required retention, purge-rejudge and eph-unify each re-opened a shape. The exhaustive mode's failures were "all the dropped-superseder family" (line 279). So: one class, recombined by every new axis the generator or the product adds.

Are fixes adding rules and state? Yes, steeply:

| | Oct 16 | Oct 22 | Oct 28 | Oct 31 | Nov 3 |
|---|---|---|---|---|---|
| commits.md §4-5 words | 388 | 1430 | 1635 | 2326 | 5090 |
| crdt.md §4.6-4.8 words | 809 | 1149 | 1164 | 1767 | 2556 |
| carve-out phrases (exception, stated limit, may read less, never received...) in commits/crdt/permissions | | 10 | 11 | 17 | 37 |
| core/engine/src/retention/ lines | 0 | 1028 | 2219 | 1843 | 3985 |
| apply/mod.rs + atomic.rs lines | 0 | 1640 | 1927 | 2263 | 3546 |
| order.rs harness lines | 0 | 0 | 1105 | 1606 | 4791 |

§4-5 doubled in the last three days. The one simplification Tess approved (death dating per node, 9492aa61, Oct 28: residues, windows and whole-replay triggers deleted) shows in the Oct 31 dip; it was eaten within three days. Of the 164 closing commits, about 15 subjects close by stating a limit or adding a harness tolerance rather than a fix (f4da2256, 4c574850, da75b21d, bb2e90a9, c36da927, 36be6bb2 ...). Retention plus atomic apply is 5.5k of 39.5k engine lines (14%); the test code aimed at it (order.rs 4.8k, it/retention.rs 2.5k, parts.rs 2.2k, waits.rs 1.0k) is twice that.

## 3. The open issues by root cause

**A. Expiry meets waits (a part dropped at T decides whether its commit applies).** applied-by-part-before-expiry, new-device-expired-part-seed-883125, unrepairable-suspect-resnapshot (seed 5288), atomic-wait-no-later-commit (killer expired). User sees: 883125 yes (one node reads an older value); atomic-wait yes (a fresh node reads stale until the aspect's next write); the others no. Loses nothing deletable, keeps nothing deleted (the value is value-less at both). Heals: atomic-wait on the next write; 883125 only by a writer's re-snapshot, and 5288 shows that repair can loop (a snapshot every 6 h per writer, forever). Tess has already said nodes may read differently when a part expired before a node could apply it (order.rs:1561).

**B. A keep-at-most or purge drop, then a validity flip (the R×D class of notes/convergence-study.md).** reopen-char-fallen-delete (closed: reads apart until a writer holding the char compacts, `required::reopen_char_after_drop_healed_by_repair`), purged-snapshot-residue, wide-purge-order (seed 3028 half), at-most-map-snapshot-drop (closed: no flip; a death-dating difference, reads alike). User sees: a char or an older write at one node only, in honest use only when a demotion races a bounded or purged write. Loses nothing deletable; shows less. Heals when any copy exists (R1, requirements line 58); not otherwise, by requirement.

**C. Bookkeeping of bounded bodies (when a body is dated dead, counted, or kept).** expiry-no-death-on-snapshot, order-exhaustive-seed-93104, order-seed-74305-death-dated-early, order-seed-112134-bounded-held, order-seed-871301-body-at-one-node (forged mix), body-class-moves, absolute-keep-at-most. User sees: none read differently. One has a real effect: absolute-keep-at-most never erases (privacy); the rest keep a dead body longer than its bound at one node (expiry-no-death: stamps only) or count it differently. Heals: a kept body goes at the next compaction. Seven of 21 issues, and this is the family the oracle, not a user, sees.

**D. A map entry whose creation expires while a later non-expiring write sits in it (key-erased records).** expired-entry-key-kept (honest, about 1 seed in 1000 of `gap_snapshot_check`), forged-key-erased-reset and vouched-key-erased (hostile or clock skew). User sees: expired-entry-key-kept yes (k present at one node, absent at the other, permanently). spec/crdt.md §4.7 only SHOULD-advises the writer. One rule decision closes all three.

**E. What an undo restores depends on which bodies this node holds.** undo-partial-buffer, undo-valueless-blocks-absent-before, crdt-model-root-register-undo. Not divergence (undo commits are ordinary writes); decisions for Tess, not order bugs.

## 4. Judgment and options

The user-visible requirement is converging. Honest-use read divergences left: A (expiry before apply, already accepted in words), D (one rule), B (needs a demotion racing a bounded write; by requirement it heals iff a copy exists). None loses deletable data; none keeps deleted content, except absolute-keep-at-most, which is an unbuilt feature, not an order bug.

The internal agreement is endless as pursued. Family C is seven of 21, the §5 death-dating paragraph exists for it, `dating`/`orphan`/`bounded_held`/index comparison and eight excuse families exist for it, and each new axis (clock, required rules, purge by author, exhaustive) recombines it. The spec already concedes the point ("nodes holding the same commits may hold different dates", "bounds may differ"), yet the oracle asserts the agreement and every seed that disproves it costs a rule or an excuse.

Options:
1. **Finish as is.** Expect 20-60 such issues a day in and out while generators grow, §4-5 doubling every few days, and a harness nobody can read. Not recommended.
2. **Narrow the oracle and §5 to what a user sees plus privacy invariants** (recommended). Compare across orders: reads, states, rosters, pending, timelines, and after exchanging bodies (`alike_exchanged`) exactly. Replace `dating`, `orphan`, `bounded_held` and cross-order index comparison with per-node invariants: no body with no live write held past its bound plus grace; no live write held nowhere after exchange (the keep-everything oracle node holds it); no value readable after its expiry or a held purge. Keep the index digest for reopen-vs-rebuild of one node only. In commits.md §5 shrink death dating to three sentences: a node dates a death at the ts of the first superseder it held; a body drops no earlier than its bound from those dates and no later than bound plus grace after this node first saw it dead; live writes leave only with a carrier. Delete engine state kept only to agree on bodies (`body_class` rows, orphan tracking, stand-in bits where the invariant does not need them). Closes C except absolute-keep-at-most (real), folds body-class-moves and wide-purge-order's internal half. Tess gives up: nothing promised. Nodes with the same commits may keep different dead bytes for up to the bound plus grace.
3. **State the expiry exception in requirements** as a third sentence beside the two existing ones: "A part that expires before a node applies it is never received there; that node may read less until a writer's snapshot." Closes A's applied-by-part and 883125 (with one line saying a dropped expired part leaves a value-less stamp or nothing; pick nothing). Cap the re-snapshot loop (5288) by "skip when this writer's newest snapshot was taken from its current state". Tess gives up: a device that was offline past a disappearing message's expiry may show the value before it until someone compacts.
4. **Decide D with one rule:** a write nested in an entry created by an expiring delta expires with it (receiver-side; today a writer SHOULD). Closes D. Tess gives up: reacting to a disappearing message with a non-disappearing reaction (already the design intent).
5. **A simpler retention model.** Relative keep at most D > 0 is the main consumer of dating; removing it (keep at most 0 after replaced, absolute T, keep at least unchanged) deletes deaths.rs's bounds work and `bounded_held`, but closes only 3-4 of the 21 (expiry-no-death, 74305, 112134, maybe 93104) because at most 0 still needs grace, carriers and parts. The chat design uses at most 0 and models history in the message itself (notes/chat-designs/c.md line 21, notes/chat.md line 7), so no first-party design needs D > 0. Worth taking only if option 2 leaves the dating code still growing; Tess would give up "erase a replaced value D after replacement" as a per-edit rule (apps model it as expiring fields). Taken later (Tess): only the timed deletes and the D arithmetic went; deaths.rs and `bounded_held` stay, since keep at least and at most 0's grace still date deaths.

Recommendation: 2 + 3 + 4 together, then finish. Finishing takes: the three spec edits (requirements one sentence; commits.md §5 dating paragraph; crdt.md §4.7 nesting rule), the oracle rewrite (order.rs: delete `dating`/`orphan`/`bounded_held`/cross-order index diff, add the three invariants, keep `alike_exchanged`), closing or merging the C issues, and leaving B to R1 (already built). Then hold the line: a seed where bodies or dates differ but reads agree and the invariants hold is not an issue. That also ends the pattern of the last twelve days, where a stricter oracle than the requirement wrote the spec.
