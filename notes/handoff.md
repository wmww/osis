# Handoff to the next coordinator
> Summary: Where the permissions and keys work stands for whoever coordinates next: Tess's standing guidance, owner removal (steps 0-1 and step 2 stage A built), findings from unmerged branches that exist only here, open questions, other open work in rough priority, process lessons. Rewrite or delete once taken.

Read CLAUDE.md, notes/coordination.md, notes/owner-removal-plan.md and notes/questions-for-tess.md first.

## Tess's standing guidance
- Rethink and rewrite, don't tack on. A precisely stated design problem beats a hollow finished build. Coordinators may change the design within the requirements' words or spirit.
- Requirements state properties we care about, not shrink-wrapped behaviour. No features built on protocol side effects (e.g. leaving writes out of a frontier on purpose as a recovery tool).
- Admin disputes are forks tolerated indefinitely; no rule may wait for a dispute to be "settled".
- Greenfield is cheap: build reference models and TLA checks freely. Model-check every major design change first; the models have found real holes every time.
- Ask Tess questions one at a time, explaining the trade-off and why users care.

## Owner removal (notes/owner-removal-plan.md)
- Built: step 0 (keys at depth 0), step 1 (roster snapshots deleted).
- Built: step 2 stage A (ownerless things derive). Next: stage B, staged in issues/owner-to-first-admin.md (B one record and one authority class, C words, D API and CLI). Build step 3 (disputes) right after B: between them a removed admin can backdate and take any thing back. Stage D overlaps the API work in issues/api-after-owners.md: coordinate.
- Steps 3 and 6 are de-risked by models (core/test/roles-model `trust`; core/test/tla/sides).

## Findings from branches that never reached main
These branches are gone; what they found is recorded only here. Redo the work from these notes.
- **keys-tidy**: (1) a grant to a holder whose keyset is blocked should go through with the holder left out (`Sealed::Out`), not wait; (2) a removal's own epoch counted as departed before its edge write is applied: reported, unconfirmed; recheck against the departure rule in spec/crypto.md §4. (3) Bounding rotation names (issues/rotation-names-grow.md): the issue's "chain coverage through supersedes" proposal leaks (a TLA instance found it); a sound base-chain rule breaks when a base rotation turns invalid. Three options were drafted for Tess; they need redoing.

## Open questions for Tess (notes/questions-for-tess.md)
Q12 (depth 0 bends, with the readers leak: mark or limit), Q11 (three kept limits), Q5 realms (on hold until owners settle).

## Other open work, rough priority
- issues/lockout-recovery-without-omission.md: lockout recovery as an ordinary removal (notes/lockout-recovery.md); until built, a deliberate lockout has none.
- issues/gone-body-drop-seeds.md, issues/settled-seed-7032.md: keep-at-most drops; the order harness's shrink needs a time budget.
- issues/role-history-join-cost.md: a join of 10^4 role writes takes 2-3 CPU-minutes; evaluating from scratch takes about 2 s.
- issues/eph-churn-delete-upload-loop.md: snapshot storm; a fix was too costly; re-study.
- Periodic checks (notes/coordination.md) are overdue after many merges: run them when the box is quiet.
- core/test/held-model covers retention, validity and apply; extend it with trust sets for step 3.

## Process lessons
- If a model's usage limit hits mid-task, commit the agent's worktree as WIP and relaunch on another model in the same worktree.
- A branch's own new randomized harness runs once at `OSIS_FULL=1` before merge (plain sizes hid a 4.6% failure rate once).
- On a branch with earlier unmerged commits, squash only to the tip you started from, never the merge base.
- Main moves under long branches: on rebase, rewrite prose into main's terms rather than resolving conflicts mechanically.
