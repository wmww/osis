# Handoff to the next coordinator
> Summary: State of the project for a coordinator working autonomously while Tess is away: branches to review or delete, decisions made in the last session and where they live, the queued work in a suggested order, the new test rules, and how to proceed without Tess. Delete or rewrite this note once its items are taken.

Written on ostrich with main at the commit that adds this note. Nothing is running: no agents, all five worktrees clean and detached. Read CLAUDE.md, notes/coordination.md and notes/core-triage.md first.

## Working without Tess
- Tess will not answer for a while. A question that needs her goes into notes/questions-for-tess.md (plain words, options, a recommendation), and you move on to other work; do not stop. Where the work cannot wait and the choice is cheap to reverse, take the recommended option and say so in the question.
- devbox is spun down (Tess): ostrich is the only box working, so this coordinator owns every issue area, devbox's included (cli, api, schema, tests and the rest of its list in notes/coordination.md), and runs every periodic check. No claims or channel posts are needed. The osis chat channel is stopped (notes/dogfood.md); Tess will set up a new one on a newer osis.
- Standing priorities (Tess): security, data loss and the core first; simple and verifiable beats fast; refactors complete; rare hostile shapes inside data the writer may write are very low priority (notes/core-triage.md §1 D).

## Branches
| branch | state | do |
|---|---|---|
| `origin/eph-lane` | eph-unify step C, +1851/-2304, partly reviewed, no verdict; whole-commits 2b waits on it | issues/eph-lane-review.md: fresh reviewer of the last reviewer's fixes, trace churn seed 9130190 (a possible upload/delete storm) first, then merge or discard; delete the branch on origin |
| `origin/crdt-leftovers` | two attempts at crdt issues, a review said neither is ready | issues/crdt-leftovers-branch.md: probably restart from the issues; keep its list-expiry oracle; delete the branch on origin |

## Decided last session (all recorded; build from these)
- Kick frontiers: commit IDs only, one system; kept-history removal cost is a stated limit (spec/requirements.md Cost). The hash DAG, per-session heads and F4 links are dropped. ID batches are the fallback if costs ever hurt (notes/frontier-study.md §11).
- Dropped bodies coming back after a revocation: keep the rule, build it simple and robust; download and CPU are cheap in this corner (issues/drop-rejoin-robust.md, seven items, start with the debug rebuild check).
- Keep at most: drop "D after replaced" for D > 0; keep "0 after replaced" and absolute T (issues/keep-at-most-relative.md).
- Moving a thing to another owner: removed (branch remove-moves); notes/moves.md says what could be built later.
- Roster privacy: notes/roster-names.md option 2 (issues/keyset-names-placement-rosters.md).
- Key rotation: the requirements study is done (notes/keys-requirements-study.md); two questions wait in notes/questions-for-tess.md (unstamped removals as key departures; depth-0 nesting for keys). Option 2 of roster-names is moot if the second is accepted.
- Tests: per-branch oracle sizes are a tenth of full by default, `OSIS_FULL=1` in periodic runs only; no rerun of run ranges; one all-core run per box; a study, not a third patch, after a second seed-found fix in one area (notes/coordination.md, notes/test-value-study.md).

## Suggested order
1. eph-lane: merged (item 269).
2. Whole commits steps 2b, 3, 4 (issues/whole-commits.md, notes/whole-commits.md): deletes the cross-thing waits and two requirement exceptions.
3. issues/drop-rejoin-robust.md item 5 (rebuild check after every transaction in debug builds): cheap, and it will find what the rest of that issue fixes. Then its items 2, 1, 3, 4, 7, with the reference model (6) alongside.
4. The simplifications keep-at-most-relative and roster option 2 (remove-moves is done). Each deletes code and spec; spec/ describes only what is built, so each lands its own spec edit.
5. notes/core-triage.md A list: pending-unbounded and purged-pending-unchecked need a bound (re-check after whole commits: pending shrinks to parts on unheld things), epoch-establishment-redesign's review, ephemeral-undo-no-authority, expired-entry-key-kept.
6. crdt-leftovers decision; the rest of core-triage by rank.
Periodic checks and simplification passes per notes/coordination.md, with `OSIS_FULL=1`. After whole commits and the simplifications land, a spec pass: spec/commits.md §4-5 should shrink a lot (it grew from 388 to about 6900 words in three weeks of seed fixes).

## Tools and costs
- `tools/agent-times.py` (default: the session that last ran agents) shows per agent the minutes per kind of work; the watchdog reads it with `--since` and `--long 3`.
- Quiet-box costs (notes/build.md): gate about 4 min, tier 1 about 2.5 min / 1900 CPU-s, the whole per-branch oracle set about 2.5 min / 950 CPU-s.
- Worktree targets are 15-29 GB against 11-12 expected: `wt` cannot prune under noatime (notes/complaints/session-wrapup.md); disk is fine (about 490 GB free); delete and rebuild one that grows past about 30 GB.
