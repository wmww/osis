# Core triage
> Summary: Every open issue sorted into security (A), honest data loss (B), honest correctness/convergence (C), hostile-only corner (D), perf/cost (E), optional/tooling (F), the A-C ones ranked, with what waits on in-flight work (whole commits 2b-5, drop-rejoin 1+2) or on Tess's two keys questions; then the requirements that kept generating fix rounds and where each stands now. Issue files stay the source of detail.

Refreshed after item 272 (keep at most D > 0 removed), with 97 files in issues/. Since the first version: moves removed (270), eph-lane merged (269), a debug rebuild check added (271), and these closed: until-ending-drop, absolute-keep-at-most, ephemeral-undo-no-authority, expired-entry-key-kept, purge-keeps-repeated-key, set-hosts-other-devices-links, revert-tells-hidden-placement, inbox-hint-names-others-label, purged-pending-unchecked, spec-audit-validity, repudiation-takes-honest-rotation (stated limit), wide-purge-order and the order seeds (order-narrow, d73), frontier-clobbers-history (IDs only), ephemeral-data, purged-snapshot-residue (moot with moves; follow-up in drop-rejoin-robust item 2).

## 1. Triage

Categories: **A** security (leak of purged or expired content, privilege, forgery); **B** data loss on an honest path; **C** core correctness or convergence on an honest path; **D** hostile-only corner, a stated limit is a candidate; **E** perf/cost; **F** optional feature, tooling, cleanup. Size: S (a day), M (a task with review), L (a design or several tasks). Waits: **WC** whole commits 2b-5 (in flight: 2b, one blob per commit); **DR** drop-rejoin-robust items 1+2 (in flight: one rebuild path, leftovers as bodies); **Q2** notes/questions-for-tess.md question 2 (a group never looks inside its member actors). "Unverified": not replayed on current main.

### In flight
- **whole-commits** (2b building; 3 deletes the cross-thing waits, 4 the per-part strip, 5 closes atomic-wait-no-later-commit and session-sources rule 5).
- **drop-rejoin-robust** (item 5 done; 1+2 in flight; then 3, 4, 7, 6).

### A-C, ranked (severity first, then size)

| # | Issue | Cat | Size | Why here |
|---|---|---|---|---|
| 2 | order-seed-91730013-expired-in-snapshot | A? | M | Undiagnosed: as made, a snapshot still holds an expired write's value two hours past T. If real, expired content kept. Replay first (unverified). Possibly the copy class fixed by copies-gone (seed 7520036); replay. |
| 4 | purge-no-reset-older-value | A?/C | S to diagnose | A purge without a reset reads `None` at the admin and an older value at a new device. Check whether content the user believes gone shows, or whether it is the accepted 2B limit. |
| 5 | pending-unbounded | A | M | A reader or inbox sender grows what a node keeps pending, for good. Needs Tess's bound. **WC**: step 3 shrinks pending to parts on unheld things; re-check then. |
| 6 | purged-values-in-waiting-copies | A | M | Purged values sit in waiting copies (part and request both waiting for the record; a blob kept for a junk-held slot; an unnamed waiting snapshot). **WC**, with #5. |
| 7 | keyset-names-placement-rosters | A | L | Readers of A receive members' device rosters (Confidentiality breach). **Q2**: option A makes it moot; else build roster option 2 (decided). |
| 9 | epoch-establishment-redesign | A | M | Frozen coverage built; its review and three open cases remain. **Q2**: mostly moot under A. |
| 10 | hidden-writes-not-swept | A | M | Two honest flows (edit after a parent reset, payload edit of a non-current enum case) keep hidden bytes; needs a concurrent edit; reads never show them. |
| 11 | fork-held-by-non-rotators | B | M | A current epoch only a demoted writer holds stays unreadable to everyone else. Rare honest shape; stays under Q2 either way. |
| 12 | covered-body-new-label | B | L | A covered body is may-hold, so hosts can end with no copy of a body retention keeps. Two fixes tried and rejected. |
| 13 | revoke-needs-whole-tree | B | designed | Writes at hosts the remover cannot reach are lost on removal (re-grant recovers); cross-group pend and linked headers are the gaps. |
| 14 | atomic-wait-no-later-commit | B | accepted | A commit waits for a dropped part when nothing later is left; self-healing. **WC**: closed by step 5. |
| 15 | route-not-told | B | stated | A co-admin that never met a holder cannot tell it a thing's first label (spec/sync.md §3). |
| 16 | unmet-sender-burst | B | stated | Shares past `INBOX_WAITING` from someone not met come back only at the 90-day re-send (coordinator: option 3, send the card first). |
| 17 | order-purge-seed-9160006 | C | M | Reads differ by arrival order (purge, demotion, a nested map); on main before and after moves. Untriaged; replay after **DR**. |
| 18 | eph-churn-delete-upload-loop | C/E | M | A compaction snapshot storm (upload and delete per pass, forever) on an honest path. Fix branch `snapshot-storm` too costly; parked behind **DR**. |
| 19 | list-mark-lost-on-fall | C | M | An un-merge loses a list creation's value-less mark: order-dependent state. Simplest rule: value-less as its own bit. May go with **DR** item 1. |
| 20 | list-element-snapshot-before-expiry | C | M | A late node holding a pre-T snapshot shows others' writes in an expired list element until a post-T snapshot. Ignored repro; full fix is a simplification. |
| 21 | ephemeral-restart-reverts-diverge | C | M | 1 in 3000 seeds: a placement at one node only after restarts. Cause unknown. |
| 22 | spec-refactor-leftovers | C | S | A commit of an unknown format version may not park as the spec says; ephemeral writes by a shared key actor undecided; one rule stated twice (goes with **WC** step 3). |
| 23 | fallen-snapshot-at-its-writer | C | S | Seed 73310002 found when that op was D > 0 (now 0): replay on main first (unverified). Then an oracle decision. Related to **DR**. |
| 24 | snapshot-late-death-credit | C | S | A late-dated death drops a snapshot early at one node; reads agree. |
| 25 | vouched-key-erased | C/D | low | Honest half (clock skew around expiry): states differ, reads alike. Misstated half in D. |
| 26 | undo-valueless-blocks-absent-before, crdt-model-root-register-undo, undo-partial-buffer | C | S each | Engine and model disagree on undo corners; two need Tess's rule. |
| 27 | node-sync-gaps, clock-back-raw-timers | C | low | Transient: crossed deletes re-place within a resync; a clock jump back stalls timers by its size. |
| 28 | suspect-repair-per-launch | C | S | One extra snapshot per launch for an unsettleable report; check against the growth rule. |
| 29 | write-only-reseal-bound | C | design | A write-only re-seal stays bound when it could seal free (liveness, conservative). **Q2**: moot under A. |
| 30 | session-sources (left: 3, 6) | C/E | M each | Step 3 (demoter compacts first) is now drop-rejoin item 7; step 6 durable header forgetting. Steps 1, 2, 4, 5 built. |

### D: hostile-only, stated-limit candidates
Priority (Tess): shapes only a malicious writer can craft inside data it may write are very low priority: fix if easy, never add much complexity while the honest paths are not nailed down.
| Issue | Why | Limit to state |
|---|---|---|
| misstated-strip-key-erased-remnant | a forged snapshot leaves a hidden key-erased record no body gives; reads alike so far | may go with **DR** item 1 (rebuild from bodies) |
| forged-key-erased-reset, vouched-key-erased (misstated half) | needs forged valid snapshots | converges at T; one creation per dot for honest writers |
| linked-header-junk-record | a reader's junk ahead of a true `created.0` copy with a linked list | a new upload replaces it |
| hint-wrap-flip | a hostile host delays a label's real entries before `label.0` is held (traced, not run) | availability only; S fix (never replace a wrap that opens under any held group) |
| header-list-decode-memory, large-value-read-memory, invalid-arrival-replays-aspect, eph-node-cost-bounds | memory or CPU a signed hostile writer or forger can cost a reader | caps as stated |
| deposit-seed-reaches-departed, fresh-deposit-seed-readable-by-departed | a departed holder keeps depositing junk | accepted residual |
| keyset-name-later-admin-path | the lost-device window, an ignorant boxer | accepted residual; **Q2**: moot under A |
| epoch-derived-same-secret | insider disruption above 2^62 | low |
| host-hub-stall, sync-log-scan, inbox-full-walk-scale | bounded DoS cost at a host or node | rates and caps as stated |
| cli-proxy follow-ups (rule 4 answer, no call deadline, Auth guesses) | a hostile attached node or client | listed as limits in the issue |
| store-unit-length-leak | plaintext row names link a slot's versions for a forensic reader | state, or hash row names |

### E: perf and cost (wait)
big-map-rewrite-cost, chat-add-cost, covered-cost-whole-snapshot, crdt-seq-linearization-cost, durable-decode-bound (left: the writer's whole-state snapshot), frontier-certificate-cost (re-measure since ID-only frontiers; close if the split is not worth it), idle-pass-per-label, long-aspect-cost, node-core-gaps, node-sequences-not-paged, perm-eval-cost, rotation-chain-cost (**Q2**: mostly moot under A), sync-step-cost, text-redelete-recompute-cost, net-cleanup (listener backlog).

### F: optional features, API, tooling, cleanup (wait or do when touched)
account-rename, api-deferred, api-knows-empty, api-leaving-give-up, api-review, app-attach-daemon, app-chat-multiline, app-group-helper, grant-rename-multi-actor, history-less-grant, partial-history-fetch, schema-discovery, cli-own-admission (label-ID admission), cli-proxy (e, f, g), magic-number-review, root-key-erasure-tier, pending-grant-unreachable (deletable machinery), eph-unify (left: D undo over held bodies, E durable auto-compaction), eph-unpaged-cover (memory pages), crdt-leftovers-branch (decide, then delete `origin/crdt-leftovers`; its list-expiry oracle is worth keeping), host-timed-delete-unused (after **WC** 2b), engine-cleanup, mid-cleanup, spec-audit-engine-rest, spec-audit-protocol, spec-audit-sync, tests-unbuilt, validity-conformance-vectors, seed-pinned-bugs-without-test, paged-apply-test-slow, build-baked-absolute-paths.

## 2. Requirement sinkholes

Rounds counted from notes/mvp-progress.md (round 13 items, devbox d-items, Wren items 269-272).

### 2.1 Atomic apply across things
About 10 multi-round items (85, 187, 229, 256, d22, d25, d31, d33, d35, d44), three exceptions on one requirement sentence. **Built**: whole commits step 3 (apply never waits for a part) deleted the Deterministic and Atomic exceptions (notes/whole-commits.md); atomic-wait-no-later-commit and revoke-needs-whole-tree's cross-group pend closed with it. Still open: pending-unbounded (shrunk), purged-values-in-waiting-copies, linked-header-junk-record.

### 2.2 Arrival-order independence under keep bounds, expiry, purge and validity flips
The largest stream (about 45 items, then d73, d77, d78, 265, 271). Done: relaxation A (oracle on reads, per-node checks; d73), 2B accepted (a drop then a flip reads alike after a writer's repair), keep at most D > 0 removed (272), and Tess's direction for the rest: drop-rejoin-robust (one rebuild path, leftovers as bodies, holders re-upload, brute-force refetch), with the rebuild check (271) to find the bugs. Open: order-purge-seed-9160006, fallen-snapshot-at-its-writer, snapshot-late-death-credit, list-mark-lost-on-fall, vouched-key-erased, misstated-strip-key-erased-remnant, eph-churn-delete-upload-loop; replay each after DR 1+2 before working it. Relaxation C (keep bounds act only through compaction) stays not recommended.

### 2.3 Kick cost
About 17 items. **Decided (Tess)**: commit IDs only; kept-history cost a stated limit (spec/requirements.md Cost); ID batches the fallback. Left: session-sources step 3 as drop-rejoin item 7, frontier-certificate-cost to re-measure, long-aspect-cost's kick past about 1.9e6 uncompacted commits.

### 2.4 Prompt purge
10 items. Honest path closed except waiting copies (purged-values-in-waiting-copies, waits on WC) and two undiagnosed reads (purge-no-reset-older-value, order-purge-seed-9160006). Hostile residue: forged-key-erased-reset, misstated half of vouched-key-erased (D).

### 2.5 Keys
About 29 items, three security reviews, one redesign; where the cost went: notes/keys-requirements-study.md (about 290 commits). Two questions wait on Tess (notes/questions-for-tess.md): Q1 timed shares and self-removals as non-departures (small deletion, removes the clock from keys); Q2 a group never looks inside its member actors (deletes about 2k lines; closes keyset-names-placement-rosters, keyset-name-later-admin-path, write-only-reseal-bound and most of epoch-establishment-redesign and rotation-chain-cost). If Q2 is declined: the redesign's review and roster option 2.

### 2.6 Inbox budget
6 items; converged. unmet-sender-burst is a stated limit (option 3); inbox-hint-names-others-label fixed.

### 2.7 Ephemeral
41 items before the unification; B2 (255) and C (269) put ephemeral on Core and the durable sync path. Open: eph-churn-delete-upload-loop (main's snapshot storm, not ephemeral-only), ephemeral-restart-reverts-diverge (1/3000), eph-unpaged-cover, eph-node-cost-bounds; D and E are features.

### 2.8 Removal is final: no key or value outlives its entry
Rounds: d70 delete-sticks, d75 delete-holes, the parked crdt-leftovers branch. Done: bare anchors keep no key (removed-keys: a dot's bare structure lives in its key-erased record, spec/crdt.md §5.6 Bare anchors). Open: hidden-writes-not-swept, list-mark-lost-on-fall, list-element-snapshot-before-expiry. Both list issues point to one rule (value-less as its own state bit, the map's rule). The requirement looks fine; the CRDT's anchor and mark records are where it leaks.

### 2.9 Overall
- Atomic apply and kick cost are decided and (for atomic) being built; keys waits on Tess's Q1/Q2.
- Arrival order is now one direction (drop-rejoin-robust) plus a backlog of seeds to replay after it.
- The new top of the A list is the CRDT removal tail (2.8) and two undiagnosed "value past expiry" seeds; pending storage still needs Tess's bound once whole commits shrink it.
