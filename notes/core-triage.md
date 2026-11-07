# Core triage
> Summary: Open issues sorted into security (A), honest data loss (B), honest correctness/convergence (C), hostile-only corner (D), perf/cost (E), optional/tooling (F), the A-C ones ranked, with what waits on other work; the issues not yet triaged, listed unranked; then the requirement areas that kept generating fix rounds and where each stands. Issue files are the source of detail; a ranking here is a judgment at the time it was made, so re-check an issue before working it.

Categories: **A** security (leak of purged or expired content, privilege, forgery); **B** data loss on an honest path; **C** core correctness or convergence on an honest path; **D** hostile-only corner, a stated limit is a candidate; **E** perf/cost; **F** optional feature, tooling, cleanup. Size: S (a day), M (a task with review), L (a design or several tasks). Waits: **WC** whole commits steps 4-5 (issues/whole-commits.md: the per-part strip rewrite, then cleanup); **DR** drop-rejoin-robust items 3, 4, 6, 7 (items 1, 2 and 5 built: one rebuild path, leftovers as bodies, the rebuild check). "Unverified": not replayed on current main.

## In progress
- **whole-commits**: steps 2a, 2b and 3 built (notes/whole-commits.md); 4 the per-part strip, 5 cleanup and the sealed-sections call.
- **drop-rejoin-robust**: holders re-upload, brute-force refetch, the reference model (held-model exists; issues/held-model-unpinned-rules.md), the revoker snapshot.

## A-C, ranked (severity first, then size)

| Issue | Cat | Size | Why here |
|---|---|---|---|
| purge-no-reset-older-value | A?/C | S to diagnose | A purge without a reset reads `None` at the admin and an older value at a new node. Check whether content the user believes gone shows, or whether it is the accepted limit. |
| pending-unbounded | A | M | A reader or inbox sender grows what a node keeps pending, for good. Needs Tess's bound; shrunk by whole commits (only parts on unheld things wait). |
| purged-values-in-waiting-copies | A | M | Purged values sit in waiting copies (part and request both waiting for the record; a blob kept for a junk-held slot; an unnamed waiting snapshot). With pending-unbounded. |
| epoch-establishment-redesign | A | M | The review of the direct-holder model (study C2) and its open cases remain. |
| hidden-writes-not-swept | A | M | Two honest flows (edit after a parent reset, payload edit of a non-current enum case) keep hidden bytes; needs a concurrent edit; reads never show them. |
| fork-held-by-non-rotators | B | M | A current epoch only a demoted writer holds stays unreadable to everyone else. Rare honest shape. |
| covered-body-new-label | B | L | A covered body is may-hold, so hosts can end with no copy of a body retention keeps. Two fixes tried and rejected. |
| revoke-needs-whole-tree | B | designed | Writes at hosts the remover cannot reach are lost on removal (re-grant recovers); linked headers are the gap. |
| a holder not told of a route (no issue) | B | stated | A co-admin that never met a holder cannot tell it a thing's first label (spec/sync.md §3). |
| unmet sender burst (no issue) | B | stated | Shares past `INBOX_WAITING` from someone not met come back only at the 90-day re-send (option 3: send the card first). |
| eph-churn-delete-upload-loop | C/E | M | A compaction snapshot storm (upload and delete per pass, forever) on an honest path. A fix branch was too costly. |
| list-element-snapshot-before-expiry | C | M | A late node holding a pre-T snapshot shows others' writes in an expired list element until a post-T snapshot. Ignored repro; full fix is a simplification. |
| shared-key-actor-ephemeral | C | S | Ephemeral writes by a shared key actor are undecided. |
| snapshot-late-death-credit | C | S | A late-dated death drops a snapshot early at one node; reads agree. |
| clock skew around a map entry's expiry (no issue; notes/engine-validity.md Limit) | C | stated | A post-T snapshot's value-less creation copy vouches only the key-erased record: states differ before T, reads alike. |
| node-sync-gaps, clock-back-raw-timers | C | low | Transient: crossed deletes re-place within a resync; a clock jump back stalls timers by its size. |
| suspect-repair-per-launch | C | S | One extra snapshot per launch for an unsettleable report. |
| session-sources (left: 3, 6) | C/E | M each | Step 3 (demoter compacts first) is drop-rejoin item 7; step 6 durable header forgetting. |

## D: hostile-only, accepted limits
Tess: shapes only a malicious writer can craft inside data it may write are very low priority: fix if easy, never add much complexity while the honest paths are not nailed down. Rows without an issue are accepted as stated here.

| Shape | Why | Limit |
|---|---|---|
| a forged snapshot leaves a hidden key-erased record no body gives (`validity::differing_key_copy_keeps_no_other_record_spec_crdt_4_6`) | needs a forged valid snapshot; reads alike so far | accepted |
| a map dot created under two keys (notes/crdt.md Limit) | needs a forged valid snapshot | converges at T; one creation per dot for honest writers |
| linked-header-junk-record | a reader's junk ahead of a true `created.0` copy with a linked list | a new upload replaces it |
| a hostile host holding a hinted label under another thing swaps the real host's wraps before `label.0` is held (traced, not run) | availability only (the threat model trusts hosts for that alone) | accepted; fix if ever seen: never replace a wrap that opens under any held group |
| header-list-decode-memory, large-value-read-memory, invalid-arrival-replays-aspect, eph-node-cost-bounds | memory or CPU a signed hostile writer or forger can cost a reader | caps as stated |
| fresh-deposit-seed-readable-by-departed | a departed holder keeps depositing junk | accepted residual |
| above 2^62 two derived epochs with one secret collide, an insider leaves a plain thing's derived epoch unestablished | insider disruption; such an insider can rotate anyway | accepted |
| host-hub-stall, sync-log-scan, inbox-full-walk-scale | bounded DoS cost at a host or node | rates and caps as stated |
| cli-proxy follow-ups (rule 4 answer, no call deadline, Auth guesses) | a hostile node or client at the other end | listed as limits in the issue |
| store row names link a slot's versions (notes/local-store.md, Row padding) | a forensic reader sees the write pattern, not content | accepted |

## E: perf and cost
big-map-rewrite-cost, chat-add-cost, covered-cost-whole-snapshot, crdt-seq-linearization-cost, durable-decode-bound (left: the writer's whole-state snapshot), frontier-certificate-cost (re-measure; close if the split is not worth it), idle-pass-per-label, long-aspect-cost, node-core-gaps, node-sequences-not-paged, perm-eval-cost, sync-step-cost, text-redelete-recompute-cost.

## F: optional features, API, tooling, cleanup
account-rename, api-deferred, api-leaving-give-up, app-attach-daemon, app-chat-multiline, app-group-helper, grant-rename-multi-actor, history-less-grant, partial-history-fetch, schema-discovery, cli-own-admission (label-ID admission), cli-proxy (e, f, g), magic-number-review, root-key-erasure-tier, pending-grant-unreachable (deletable machinery), eph-unify (left: D undo over held bodies, E durable auto-compaction), eph-unpaged-cover (memory pages), host-timed-delete-unused (after WC), mid-cleanup, spec-audit-engine-rest, spec-audit-sync, validity-conformance-vectors, seed-pinned-bugs-without-test, paged-apply-test-slow, build-baked-absolute-paths.

## Not yet triaged (unranked)
Grouped by their tags only; read the issue before placing it.
- Tagged security: blocked-walk-stops-at-readers, grant-audits-without-frontier, keys-depth0-removed-member-rotates.
- Waiting on Tess (`tess-call`): node-host-unify, no-server-audit, recovery-redesign, revocation-without-arbiter.
- Engine and retention: delete-required-rules, gone-body-drop-seeds, purge-and-kill-in-one-commit-no-leftover, alike-seed-913022-nested-text-after-flip, subgroup-expiry-strands-silently, removal-without-possession, parked-diagnostic, creation-record-ordinary (a proposal).
- Cost: copy-expiry-probe-cost, role-history-join-cost, rotation-names-grow.
- Tests and tooling: held-model-unpinned-rules, judgment-vectors-can-fail-shorter-order.
- Naming, app: deprecated-terms, app-workarounds.

## Requirement areas that kept generating fix rounds
- **Atomic apply across things**: settled by whole commits (a part waits alone; no cross-thing wait), which deleted the Deterministic and Atomic exceptions. Left: pending-unbounded, purged-values-in-waiting-copies, linked-header-junk-record.
- **Arrival-order independence under keep bounds, expiry, purge and validity flips**, the largest stream: the oracle compares reads plus per-node checks, not held bodies or death dates (notes/testing.md, Arrival-order differential); a drop then a flip reads alike after a writer's repair (notes/convergence-study.md); relative keep at most D > 0 is removed; drop-rejoin-robust is Tess's direction for the rest, with the rebuild check to find bugs. Open seeds to replay before working them: snapshot-late-death-credit, eph-churn-delete-upload-loop, gone-body-drop-seeds, purge-and-kill-in-one-commit-no-leftover, alike-seed-913022-nested-text-after-flip. Rejected: keep bounds acting only through compaction.
- **Kick cost**: Tess's decision: frontiers by commit ID only; kept-history cost a stated limit (spec/requirements.md Cost); ID batches the fallback. Left: session-sources step 3, frontier-certificate-cost, long-aspect-cost's kick past about 1.9e6 uncompacted commits.
- **Prompt purge**: the honest path is closed except waiting copies and an undiagnosed read (purge-no-reset-older-value). Hostile residue in D.
- **Keys**: where the cost went: notes/keys-requirements-study.md. Timed ends finalized and depth 0 (a group never looks inside its member actors, notes/crypto.md (Holder actors at depth 0)) are built; the new security-tagged keys issues above are its tail.
- **Inbox budget**: converged; a burst from an unmet sender is a stated limit.
- **Ephemeral**: on Core and the durable sync path (notes/ephemeral.md). Open: eph-churn-delete-upload-loop (not ephemeral-only), churn-cursor-rebuild-differs, eph-unpaged-cover, eph-node-cost-bounds; eph-unify D and E are features.
- **Removal is final** (no key or value outlives its entry): bare anchors keep no key (spec/crdt.md §5.6). Open: hidden-writes-not-swept, list-element-snapshot-before-expiry; both list issues point to one rule (value-less as its own state bit, the map's rule). The requirement is fine; the CRDT's anchor and mark records are where it leaks.
