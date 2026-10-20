# Hardening and sign-off
> Summary: The last plan of the MVP run: complete the spec-to-test map (every MUST tested or an issue), fresh-agent security reviews per subsystem against the attack lists in the notes, metadata and negative tests, size and performance checks at scale, a panic and dependency audit, notes brought current (notes/testing.md, notes/node.md, every "Implementation" section), plans deleted, and a final report to the owner.
> Tags: tests, security

Depends on: every other plan merged. Produces: the final state of notes/, issues/, and the report.
Reference: plans/testing.md §6, notes/testing.md (budgets, spec map), notes/sync.md (Limits; What a blind node learns), notes/permissions.md (Revocation; Links; membership model findings), spec/requirements.md (every section is a checklist). Spec trumps this plan.

## Deliverables
- Spec-to-test map regenerated (test-infra script); every MUST / MUST NOT in spec/ either cites a test or has an issue tagged `tests` naming the gap; the owner-call and escalate issues listed.
- Security review passes, one fresh opus agent per subsystem (crypto+keys, perm+flows, label+server, node-sync convergence, store, api) given the spec sections, the notes' attack and limits lists and the code, writing findings as issues (`security`) and fixing the clear ones; a second fresh agent re-reviews the fixes.
- Negative tests per "MUST NOT be able to" in spec/permissions.md and spec/sync.md; metadata tests (blind node stored bytes contain nothing from the forbidden list; padded sizes; no author linkage across labels).
- Scale checks at reduced constants (tier 2): million-key map edit is O(change); multi-GB value streamed within a memory bound; million-blob label reconciliation rounds; roster of thousands removal cost matches notes; text budget table.
- Panic audit: every fuzz target run for a budget with no crash; `clippy::unwrap_used` deny holds; dependency allowlist matches `cargo tree`; `cargo deny` clean; build time and tier-1 test time recorded in notes/testing.md.
- Notes current: notes/testing.md (what runs where, how to replay, what it does not cover), notes/node.md, each subsystem's "Implementation" section, notes/overview.md status and code map; spec TBDs all resolved or listed; every completed plan deleted.
- Final report (in notes/mvp-progress.md and to the owner): what works to spec, deviations with the requirement limit or issue that justifies each, open issues by tag, spec edits made during the run, suggested next plans (query design pass, push wake-ups, BLE, browser build).

## Steps
- [x] Map + gaps; negative and metadata tests.
- [ ] Review passes and fixes; scale checks; panic and dependency audit.
- [ ] Notes, deletions, report.

## Done when
The report is written, the owner can read notes/overview.md and know the state, and `plans/` holds only plans for future work the owner has not asked for yet. Delete this plan last.

## Progress
- Step 1 done: tools/spec_map.py rule checklist (46 rules: 42 tested, 1 issued, 3 vacuous; `--gaps` in CI), anchors cited on existing tests, new negative tests (perm owner and edge writes, link commit form, edge change/removal inbox, keep at least, QUIC auth and 0-RTT) and metadata tests (osis-node metadata.rs); no security bug found; issues/tests-spec-gaps.md.
