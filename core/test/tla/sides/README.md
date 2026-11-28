# Sides (TLA+)
> Summary: TLC model of stores and storage under a fork of a thing (notes/disputes.md, Storage under a fork): nodes on side X or Y run the ordinary sync rules over their side's validity at one store; step 6 candidates as modes. Results: at sync IDs both sides use, deletes at stores follow a "no side needs it" rule (the per-reason gate alone keeps every superseded one-side write forever); the forked thing's own sync ID works as a store branch per side, with members carrying clean bodies across; logging again once, a neutral view, per-aspect, the parties' own writes and ungated one-side covers fail.

Files: `Sides.tla` (the model), `MC.tla` (scenarios), named `.cfg` instances, `matrix.sh` (every scenario under every mode), `ASSUMPTIONS.md`. A design exploration forked from `../sync` with notes/ at hand, not an independent spec check.

## Run
`../run.sh sides` runs the named instances (about 12 min at one worker on a box at load 60). `matrix.sh [scenario] [mode]` runs scenario × mode × property, one TLC run each (`JOBS` in parallel, `PROPS` to pick properties; `TRACE_DIR=<dir>` keeps failing logs; filters are bash patterns, `'@(a|b)'` works). The whole matrix is 8 × 17 × 6 runs, about 38 min at 14 jobs under tools/heavy. Largest instance 649k states (P with branching and a concession), Q0's 485k, the rest under 160k. Don't edit `matrix.sh` while it runs (bash reads it as it goes); run a copy.

## Model
Nodes: the parties x (side X) and y (side Y), and a member m boxed by both, which may switch sides twice. One sync ID L at one store; with the fork, the parties race to register their rotation at L and the store keeps the loser's step as its second branch R of L (a sync ID's steps form a tree, spec/sync-ids.md §2), which starts with L's entries stamped under the shared steps. A body is must-not-hold or covered by reasons resting on a write being valid (a superseder, a purge, a snapshot) or invalid or not held (an invalid write's fall under purge on replace; a strong reference keeping the body's thing in the sync unit, whose verdict, outside the required set, waits for a complete pass: spec/sync-judgement.md §2); Dd is the set of writes valid on one side only.

Scenarios: **K** Y's write supersedes a pre-dispute body b0 (m on Y). **Z** as K, by a node granted on side X after the dispute (not a party's own write). **F** X's post-dispute write under purge on replace falls on side Y; an outside body u. **C** X's post-dispute snapshot covers b0 (one-side cover). **P** a purge both sides accept, on an aspect Y wrote to after the dispute. **Q** Y's post-dispute write q holds a strong reference to t, keeping it in the sync unit (q is content: nothing fetches it first); both at the store. **Q0** as Q with q not logged yet. **S** X's post-dispute write s1 superseded by X's later s2 (both valid on X only; side Y needs neither).

Gates on deletes at stores (must-not-hold and compaction): `none` (today's rules per side); `direct` no delete resting on a write by X or Y themselves; `neutral` must-not-hold also with every disputed write void; `touch` the body is not disputed and some reason holds whose write is not disputed; `exact` must-not-hold on both sides (two walks, the oracle); `aspect` no delete of a body on an aspect holding a disputed write or a reason write in Dd; `need` a reason holds on the own side and on every side the body is invalid or some reason holds (no side needs it). Other candidates: (b) `RelogOnce`; (d) `CoverOwn` (covers judged on the own side, ungated); `Fork` (the step race and store branch, `br`); `Bridge` (with the fork, a member also acts on clean bodies at the branch it reads but does not act at); `Lift` (the gate is off at R and at L once branched); `Conc` (a concession: a body that, once held, makes the node judge as side `CWin`; `concX`: y concedes, side X wins).

Properties: `NoLoss` (invariant: a body that reached a store and some side keeps live has a copy somewhere), `Quiesce` (the store settles: no endless log/delete loop), `Served` (a fresh node of a side some node is on finds at its sync IDs every body that side keeps live and someone has), `Alike` (after its switches each node holds what a fresh node of its side reads), `PurgePrompt` (a purge both sides accept leaves every sync ID), `Tidy` (without the fork, a body no side needs and some side must not hold leaves L). Weak fairness of honest steps; switches and compaction unfair.

## Results
TLC 2.19, 1 worker per run, shared 16-core box at load 20-40; Q and Q0 at 12 jobs, about 27 min at load 30-60. The other columns were run before `Pass` existed, not since: no reason of theirs waits for a pass, so it changes nothing they check (the named instances, rerun, agree). Failed properties per cell (L NoLoss, Q Quiesce, S Served, A Alike, P PurgePrompt, T Tidy; Tidy is vacuous with the fork):

| mode | K | Z | F | C | P | Q | Q0 | S |
|---|---|---|---|---|---|---|---|---|
| none | LQSA | LQSA | QSA | L | ok | LQSA | LQSA | ok |
| a-direct | ok | LQSA | ok | ok | ok | ok | L | T |
| a-neutral | ok | ok | QSA | ok | ok | LQSA | LQSA | T |
| a-touch | ok | ok | ok | ok | ok | ok | L | T |
| a-exact | ok | ok | ok | ok | ok | ok | L | T |
| a-aspect | ok | ok | ok | ok | PT | ok | L | T |
| a-need | ok | ok | ok | ok | ok | ok | L | ok |
| b | LSA | LSA | SA | LSA | ok | LSA | LSA | ok |
| d+a-touch | ok | ok | ok | L | ok | ok | L | T |
| br | L | L | S | LS | SP | L | L | ok |
| br+a-touch | ok | ok | S | ok | SP | ok | LS | ok |
| br+a-touch+lift | ok | ok | S | ok | SP | ok | L | ok |
| br+a-touch+lift+bridge | ok | ok | ok | ok | ok | ok | L | ok |
| a-touch+concX | ok | ok | ok | ok | ok | ok | ok | ok |
| a-touch+concY | ok | ok | ok | ok | ok | ok | L | ok |
| br+a-touch+lift+concX | ok | ok | ok | ok | P | ok | ok | ok |
| br+a-touch+lift+concY | ok | ok | ok | ok | P | ok | L | ok |

Named instances (`run.sh`): `kill_touch`, `purge_touch`, `strong_touch`, `branch_kill`, `branch_bridge`, `concede`, `tidy_need` pass; `kill_none` (no gate) and `strong_nowait` (Q judged without waiting for a pass) fail, the negative controls. Each 135 to 32,460 states. The other cells are `matrix.sh` runs.

Reading the branching rows: what is lost is a body first logged after the split (F: u; P: the purge) reaching only the logger's branch, fixed by members carrying clean bodies across. Lifting the gate at a branch changes no result. Q0 is a judgment resting on a write nobody logged yet: a complete pass cannot see it (concX passes it only because there the strong's side loses). With a concession, the conceded side's branch keeps what it had (P): nobody acts there any more.

What the counterexamples are, and what follows from them: notes/disputes.md, Storage under a fork.

## Not covered
Several stores, several disputes (the `need` rule over more than two sides), honest concurrent rotations under branching, a removed admin branching from an old step, keep-at-least and `nobody`, live writes surviving a kill, covers resting on deaths that rest on a disputed write, inbox and deposits, the party erasing itself on a switch, stale views, clock skew.
