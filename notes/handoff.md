# Handoff to the next coordinator
> Summary: Where the permissions and keys work stands for whoever coordinates next: Tess's standing guidance, first admins and disputes (steps 0-4 built), findings from unmerged branches that exist only here, open questions, other open work in rough priority, process lessons. Rewrite or delete once taken.

Read CLAUDE.md, notes/coordination.md, notes/disputes-plan.md and notes/questions-for-tess.md first.

## Tess's standing guidance
- Rethink and rewrite, don't tack on. A precisely stated design problem beats a hollow finished build. Coordinators may change the design within the requirements' words or spirit.
- Requirements state properties we care about, not shrink-wrapped behaviour. No features built on protocol side effects (e.g. leaving writes out of a frontier on purpose as a recovery tool).
- Admin disputes are forks tolerated indefinitely; no rule may wait for a dispute to be "settled".
- Greenfield is cheap: build reference models and TLA checks freely. Model-check every major design change first; the models have found real holes every time.
- Ask Tess questions one at a time, explaining the trade-off and why users care.

## First admins and disputes (notes/disputes-plan.md)
- Built: steps 0-4 (keys at depth 0; no roster snapshots; first admins, API and apps included; disputes in the walk; per-node sides with defaults, API and CLI).
- Next: nodes following their account's published side, steps 5-6.

## Findings from branches that never reached main
These branches are gone; what they found is recorded only here. Redo the work from these notes.
- **keys-tidy**: (1) a grant to a holder whose keyset is blocked should go through with the holder left out (`Sealed::Out`), not wait; (2) a removal's own epoch counted as departed before its edge write is applied: reported, unconfirmed; recheck against the departure rule in spec/crypto.md §4. (3) Bounding rotation names (issues/rotation-names-grow.md): the issue's "chain coverage through supersedes" proposal leaks (a TLA instance found it); a sound base-chain rule breaks when a base rotation turns invalid. Three options were drafted for Tess; they need redoing.

## Open questions for Tess (notes/questions-for-tess.md)
Q17 (hole punching and IP consent), Q15 (drafts in groups), Q12 (depth 0 bends), Q11 (three kept limits), Q5 realms (can resume: owners are gone).

## Other open work, rough priority
- issues/link-leave-splits-thing.md: after a link joiner leaves, the maker and the other joiner stop seeing each other's posts (data loss, reproduced in one chat create order).
- issues/lockout-vandal-left.md, issues/purge-harness-model-disagreements.md, issues/at-most-kill-quadratic.md.
- issues/role-history-join-cost.md: a join of 10^4 role writes takes 2-3 CPU-minutes; evaluating from scratch takes about 2 s.
- issues/eph-churn-delete-upload-loop.md: snapshot storm; a fix was too costly; re-study.
- Periodic checks (notes/coordination.md) are overdue after many merges: run them when the box is quiet.
- core/test/held-model covers retention, validity and apply; extend it with trust sets.

## Process lessons
- If a model's usage limit hits mid-task, commit the agent's worktree as WIP and relaunch on another model in the same worktree.
- A branch's own new randomized harness runs once at `OSIS_FULL=1` before merge (plain sizes hid a 4.6% failure rate once).
- On a branch with earlier unmerged commits, squash only to the tip you started from, never the merge base.
- Main moves under long branches: on rebase, rewrite prose into main's terms rather than resolving conflicts mechanically.
