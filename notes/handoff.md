# Handoff to the next coordinator
> Summary: State left by coordinator Wren (ostrich, Nov 4-5): the owner-removal plan is mid-flight (steps 0-1 built), three branches in progress, open questions for Tess, what to do next and in what order. Delete or rewrite once taken.

Read CLAUDE.md, notes/coordination.md, notes/owner-removal-plan.md, notes/questions-for-tess.md first. Session log: notes/mvp-progress.md "Wren session" (items 269-298).

## Tess's standing guidance from this session (also in memory)
- Rethink and rewrite, don't tack on; a precisely stated design problem beats a hollow finished build; coordinators may change the design within the requirements' words or spirit.
- Requirements state properties we care about, not shrink-wrapped behaviour; no features on protocol side effects (e.g. deliberate frontier omission as a recovery tool).
- Admin disputes are forks tolerated indefinitely; no rule may wait for a dispute to be "settled".
- Greenfield is cheap: build reference models and TLA checks freely. Every major design change this session was model-checked first, and the models found real holes each time.
- Ask Tess questions one at a time, explaining the trade-off and why users care.

## Branches in flight (local; agents told to commit WIP and release)
| branch | state | next |
|---|---|---|
| `keys-tidy` | WIP, not fully tested. Done: grant to a blocked holder goes through as Out; fix in `NamesHeld::departed` (a removal's own epoch counted before its edge write; on main too). Blocked: bounding rotation names: the issue's proposal leaks (TLA `F_naive_chain`); a sound base-chain rule breaks when a base rotation turns invalid; three options for Tess in issues/rotation-names-grow.md (state at top). Prototype on local `keys-tidy-names-proto`. | run tier 1/clippy/harnesses, review, merge the done parts; put the names options to Tess; then lockout recovery |
| `readers-leak` | Model merged to main. Leak confirmed; rule (a) fails with a second G admin who doesn't read A, and so does main's merged alone-above fix (`D0_above_g2`). Candidate "mark" (a rotation records the A key it left A out at; re-add only at a newer A key) passes but needs a wire field; or accept as a stated limit. | put mark-vs-limit to Tess as part of Q12; it bears on the merged item 297 too |
| `firstadmin-model` | Done, NOT merged (989c9a3eb): rebase conflicts with readers-leak in Depth0.tla, Depth0MC.tla, README, run.sh (both added constants/instances; merge both sides). Results: key-access flip on first-admin removal is safe given one spec rule (judge key access over held grants minus known removed actor edges); derivation after a thing gets own secrets needs a rule (a derived epoch written under counts as a current epoch of T, so its writer merges T); stated limit for a write concurrent with its author's removal. Details in the branch's issues/owner-to-first-admin.md Risks. | merge (resolve TLA conflicts, rerun run.sh small); write both rules into spec with stage A |
Check `git branch` and `wt list`; any worktree still claimed with no running agent: commit WIP and release.

## Owner-removal plan (notes/owner-removal-plan.md)
- Step 0 keys at depth 0: built (items 295-297). Step 1 roster snapshots deleted: built (298).
- Step 2 owners → first admins: staged build plan in issues/owner-to-first-admin.md (A derive from first admin, B one record/one authority class, C renames, D API/CLI). Start A after keys-tidy merges (both touch key derivation). Build step 3 right after B (security gap between them). Stage D conflicts with Tess's other session's API work (issues/api-after-owners.md): coordinate.
- Step 3 disputes: de-risked (core/test/roles-model trust.rs; three rule problems in plan step 3). Step 6 hosts: de-risked and Q9 closed (core/test/tla/sides; host branching + "no side needs it").

## Security first
- issues/forged-departs-mark-entry.md (new, untested): a self-removing member may add a history entry saying its own removal is covered, so nobody rotates and it keeps reading. Confirm with a test and fix before other keys work.

## Open questions for Tess (notes/questions-for-tess.md)
- Q12: depth 0 bends slightly (a device holding a member group's keys won't hand out its stale key). Recommended: accept. Already built (297).
- Q13: anyone with write on G may create a thing whose first admin is G. Recommended: yes. Needed before step 2 stage B.
- Q11: three small limits from the requirements pass. Q5 realms: on hold until owners settle.

## Other open work, in rough priority
- issues/gone-body-drop-seeds.md, issues/settled-seed-7032.md (pre-existing keep-at-most drops; the order shrink needs a time budget).
- issues/role-history-join-cost.md (a join of 10^4 role writes takes 2-3 CPU-min; from-scratch eval is ~2 s).
- issues/eph-churn-delete-upload-loop.md: snapshot storm; branch `snapshot-storm` parked (fix too costly); re-study now that items 274/283 changed held bodies.
- Periodic checks: last run 15 (after item 276). Many merges since: run them when the box is quiet (notes/coordination.md; the tier-2 command now skips release-only benches).
- Model (core/test/held-model) covers retention/validity/apply; extend with trust sets for step 3.

## Process notes
- Fable usage ran out mid-session; opus took over cut-off work from WIP commits. If a model limit hits, commit the agent's worktree as WIP and relaunch on another model in the same worktree.
- A branch's own new randomized harness must run once at OSIS_FULL=1 before merge (plain sizes hid a 4.6% failure rate).
- On a branch with earlier unmerged commits, squash only to the tip you started from, never the merge base.
- Main moves under long branches (Tess's other session refactors the API and sweeps wording): rebase rewrites prose into main's terms, not mechanical conflict resolution.
