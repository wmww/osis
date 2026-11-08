# Sides (TLA+)
> Summary: TLC model of hosts and storage under a fork of an actor (notes/disputes-plan.md step 6): nodes on side X or Y run the ordinary sync rules over their side's validity at one host; step 6 candidates as modes. Results: at labels both sides use, deletes at hosts follow a "no side needs it" rule (the plain per-reason gate keeps every superseded one-side write forever); the forked actor's own label works as a host branch per side, with members carrying clean bodies across; re-upload once, a neutral view, per-aspect, the parties' own writes and ungated one-side covers fail.

Files: `Sides.tla` (the model), `MC.tla` (scenarios), named `.cfg` instances, `matrix.sh` (every scenario under every mode), `ASSUMPTIONS.md`. A design exploration forked from `../sync` with notes/ at hand, not an independent spec check.

## Run
`../run.sh sides` runs the named instances (about 15 s at one worker). `matrix.sh [scenario] [mode]` runs scenario × mode × property, one TLC run each (`JOBS` in parallel, `PROPS` to pick properties; `TRACE_DIR=<dir>` keeps failing logs; filters are bash patterns, `'@(a|b)'` works). The whole matrix is 8 × 21 × 6 runs; the branching rows take about 35 min at 14 jobs, load 30. Largest instance 649k states (P with branching and a concession), the rest under 140k. Don't edit `matrix.sh` while it runs (bash reads it as it goes); run a copy.

## Model
Nodes: the parties x (side X) and y (side Y), and a member m boxed by both, which may switch sides twice. One label L at one host; with the fork, the parties race to register their rotation at L and the loser makes R: a replacement label, or with branching the host's second branch of L, which starts with L's entries stamped under the shared steps. A body is must-not-hold or covered by reasons resting on a write being valid (a superseder, a purge, a snapshot) or invalid (an invalid write's fall under purge on replace, a placement); Dd is the set of writes valid on one side only.

Scenarios: **K** Y's write supersedes a pre-dispute body b0 (m on Y). **Z** as K, by a device X granted after the dispute (not a party's own write). **F** X's post-dispute write under purge on replace falls on side Y; an outside body u. **C** X's post-dispute snapshot covers b0 (one-side cover). **P** a purge both sides accept, on an aspect Y wrote to after the dispute. **Q** Y's post-dispute placement keeps t in the label; role commits uploaded and fetched first. **Q0** as Q without that order. **S** X's post-dispute write s1 superseded by X's later s2 (both valid on X only; side Y needs neither).

Gates on deletes at hosts (must-not-hold and compaction): `none` (today's rules per side); `direct` no delete resting on a write by X or Y themselves; `neutral` must-not-hold also with every disputed write void; `touch` the body is not disputed and some reason holds whose write is not disputed; `exact` must-not-hold on both sides (two walks, the oracle); `aspect` no delete of a body on an aspect holding a disputed write or a reason write in Dd; `need` a reason holds on the own side and on every side the body is invalid or some reason holds (no side needs it). Other candidates: (b) `ReupOnce`; (c) `Fork`; (d) `CoverOwn` (covers judged on the own side, ungated); `Bridge` (with the fork, a member also acts on clean bodies at the label it reads but does not act at); `HostBranch` (the fork as a host branch, `br`); `Lift` (the gate is off at R and at L once branched); `Conc` (a concession: a body that, once held, makes the node judge as side `CWin`; `concX`: y concedes, side X wins).

Properties: `NoLoss` (invariant: a body that reached a host and some side keeps live has a copy somewhere), `Quiesce` (the host settles: no endless upload/delete loop), `Served` (a fresh node of a side some node is on finds at its labels every body that side keeps live and someone has), `Alike` (after its switches each node holds what a fresh node of its side reads), `PurgePrompt` (a purge both sides accept leaves every label), `Tidy` (without the fork, a body no side needs and some side must not hold leaves L). Weak fairness of honest steps; switches and compaction unfair.

## Results
TLC 2.19, 1 worker per run, shared 16-core box at load 20-40. Failed properties per cell (L NoLoss, Q Quiesce, S Served, A Alike, P PurgePrompt, T Tidy; Tidy is vacuous with the fork):

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
| c | L | L | S | LS | SP | L | L | ok |
| c+a-touch | S | S | S | S | SP | S | LS | ok |
| c+a-touch+bridge | S | S | ok | S | ok | S | LS | ok |
| c+a-touch+lift | S | S | S | S | SP | S | LS | ok |
| d+a-touch | ok | ok | ok | L | ok | ok | L | T |
| br | L | L | S | LS | SP | L | L | ok |
| br+a-touch | ok | ok | S | ok | SP | ok | L | ok |
| br+a-touch+lift | ok | ok | S | ok | SP | ok | L | ok |
| br+a-touch+lift+bridge | ok | ok | ok | ok | ok | ok | L | ok |
| a-touch+concX | ok | ok | ok | ok | ok | ok | ok | ok |
| a-touch+concY | ok | ok | ok | ok | ok | ok | L | ok |
| br+a-touch+lift+concX | ok | ok | ok | ok | P | ok | ok | ok |
| br+a-touch+lift+concY | ok | ok | ok | ok | P | ok | L | ok |

Named instances (`run.sh`): `kill_touch`, `purge_touch`, `place_touch`, `branch_kill`, `branch_bridge`, `concede`, `tidy_need` pass; `kill_none` (no gate) fails as listed above, the negative control. Each 40 to 4,380 states, 1-4 s. The other cells are `matrix.sh` runs.

Reading the new rows: with branching, the losses of the replacement fork (c) go; what is left is a body first uploaded after the split (F: u; P: the purge) reaching only the uploader's branch, fixed by members carrying clean bodies across. Lifting the gate at a branch changes no result. Q0 is the old unheld-placement shape (concX passes it only because there the placement's side loses). With a concession, the conceded side's branch keeps what it had (P): nobody acts there any more.

What the counterexamples are, and what follows from them: notes/disputes-plan.md, step 6.

## Not covered
Several hosts, several disputes (the `need` rule over more than two sides), honest concurrent rotations under branching, a removed admin branching from an old step, keep-at-least and `nobody`, live writes surviving a kill, covers resting on deaths that rest on a disputed write, inbox and deposits, the party erasing itself on a switch, stale views, clock skew.
