# Handoff to the next coordinator
> Summary: State of the project for a coordinator working autonomously while Tess is away: branches to review or delete, decisions made in the last session and where they live, the queued work in a suggested order, the new test rules, and how to proceed without Tess. Delete or rewrite this note once its items are taken.

Written on ostrich with main at the commit that adds this note. Nothing is running: no agents, all five worktrees clean and detached. Read CLAUDE.md, notes/coordination.md and notes/core-triage.md first.

## Working without Tess
- Tess will not answer for a while. A question that needs her goes into notes/questions-for-tess.md (plain words, options, a recommendation), and you move on to other work; do not stop. Where the work cannot wait and the choice is cheap to reverse, take the recommended option and say so in the question.
- The osis chat channel between the boxes is stopped (notes/dogfood.md); Tess will have a new one set up. Until then, if devbox's coordinator is also active (see `git log` authors and the d-numbered items in notes/mvp-progress.md), claim an issue with a commit to main adding a `Claimed: <name> (<box>, <branch>)` line to it before `wt claim`, and pull before every push.
- Standing priorities (Tess): security, data loss and the core first; simple and verifiable beats fast; refactors complete; rare hostile shapes inside data the writer may write are very low priority (notes/core-triage.md §1 D).

## Branches
| branch | state | do |
|---|---|---|
| `origin/eph-lane` | eph-unify step C, +1851/-2304, partly reviewed, no verdict; whole-commits 2b waits on it | issues/eph-lane-review.md: fresh reviewer of the last reviewer's fixes, trace churn seed 9130190 (a possible upload/delete storm) first, then merge or discard; delete the branch on origin |
| `origin/crdt-leftovers` | two attempts at crdt issues, a review said neither is ready | issues/crdt-leftovers-branch.md: probably restart from the issues; keep its list-expiry oracle; delete the branch on origin |
| `origin/app-review2` | stale: all 10 commits are on main under the same subjects (checked) | `git push origin --delete app-review2` |
| local `session-25-rv` | stale: its work merged as item 239; the other commit is throwaway review probes | `git branch -D session-25-rv` |
| local `dogfood-bin`, `periodic-14`, `session-2`, `client-port-read` | fully merged (0 commits ahead) | `git branch -d` |

## Decided last session (all recorded; build from these)
- Kick frontiers: commit IDs only, one system; kept-history removal cost is a stated limit (spec/requirements.md Cost). The hash DAG, per-session heads and F4 links are dropped. ID batches are the fallback if costs ever hurt (notes/frontier-study.md §11).
- Dropped bodies coming back after a revocation: keep the rule, build it simple and robust; download and CPU are cheap in this corner (issues/drop-rejoin-robust.md, seven items, start with the debug rebuild check).
- Keep at most: drop "D after replaced" for D > 0; keep "0 after replaced" and absolute T (issues/keep-at-most-relative.md).
- Moving a thing to another owner: remove it; notes/moves.md says what could be built later (issues/remove-moves.md).
- Roster privacy: notes/roster-names.md option 2 (issues/keyset-names-placement-rosters.md).
- Key rotation: a read-only study of which requirement forces its cost (issues/keys-requirements-study.md, fable; results go to questions-for-tess).
- Tests: per-branch oracle sizes are a tenth of full by default, `OSIS_FULL=1` in periodic runs only; no rerun of run ranges; one all-core run per box; a study, not a third patch, after a second seed-found fix in one area (notes/coordination.md, notes/test-value-study.md).

## Suggested order
1. Branch cleanup above (minutes), then eph-lane: it blocks whole-commits 2b.
2. Whole commits steps 2b, 3, 4 (issues/whole-commits.md, notes/whole-commits.md): deletes the cross-thing waits and two requirement exceptions.
3. issues/drop-rejoin-robust.md item 5 (rebuild check after every transaction in debug builds): cheap, and it will find what the rest of that issue fixes. Then its items 2, 1, 3, 4, 7, with the reference model (6) alongside.
4. The three simplifications: remove-moves, keep-at-most-relative, roster option 2. Each deletes code and spec; spec/ describes only what is built, so each lands its own spec edit.
5. issues/keys-requirements-study.md (one fable agent, no code).
6. notes/core-triage.md A list: pending-unbounded and purged-pending-unchecked need a bound (re-check after whole commits: pending shrinks to parts on unheld things), epoch-establishment-redesign's review, ephemeral-undo-no-authority, expired-entry-key-kept.
7. crdt-leftovers decision; the rest of core-triage by rank.
Periodic checks and simplification passes per notes/coordination.md, with `OSIS_FULL=1`. After whole commits and the simplifications land, a spec pass: spec/commits.md §4-5 should shrink a lot (it grew from 388 to about 6900 words in three weeks of seed fixes).

## Tools and costs
- `tools/agent-times.py` (default: the session that last ran agents) shows per agent the minutes per kind of work; the watchdog reads it with `--since` and `--long 3`.
- Quiet-box costs (notes/build.md): gate about 4 min, tier 1 about 2.5 min / 1900 CPU-s, the whole per-branch oracle set about 2.5 min / 950 CPU-s.
- Worktree targets are 15-29 GB against 11-12 expected: `wt` cannot prune under noatime (notes/complaints/session-wrapup.md); disk is fine (about 490 GB free); delete and rebuild one that grows past about 30 GB.
