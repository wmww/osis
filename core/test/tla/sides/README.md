# Sides (TLA+)
> Summary: TLC model of hosts and storage during an admin dispute (notes/owner-removal-plan.md step 6): nodes on side X or Y run the ordinary sync rules over their side's validity at one host; step 6 candidates as modes. Results: deletes at hosts must be gated on disputed writes (per reason or per aspect); re-upload once, a neutral view, a gate on the parties' own writes and ungated one-side covers fail; a label fork is needed for keys but splits what each side can reach.

Files: `Sides.tla` (the model), `MC.tla` (scenarios), named `.cfg` instances, `matrix.sh` (every scenario under every mode), `ASSUMPTIONS.md`. A design exploration forked from `../sync` with notes/ at hand, not an independent spec check.

## Run
`../run.sh small sides` runs the named instances (11, about 30 s). `matrix.sh [scenario] [mode]` runs scenario × mode × property, one TLC run each (`JOBS` in parallel, 330 runs about 13 min at load 30; `TRACE_DIR=<dir>` keeps failing logs). Largest instance 78k states (P with the fork).

## Model
Nodes: the parties x (side X) and y (side Y), and a member m boxed by both, which may switch sides twice. One label L at one host; with the fork, the parties race to register their rotation at L and the loser makes R. A body is must-not-hold or covered by reasons resting on a write being valid (a superseder, a purge, a snapshot) or invalid (an invalid write's fall under keep at most 0, a placement); Dd is the set of writes valid on one side only.

Scenarios: **K** Y's write supersedes a pre-dispute body b0 (m on Y). **Z** as K, by a device X granted after the dispute (not a party's own write). **F** X's post-dispute write under keep at most 0 falls on side Y; an outside body u. **C** X's post-dispute snapshot covers b0 (one-side cover). **P** a purge both sides accept, on an aspect Y wrote to after the dispute. **Q** Y's post-dispute placement keeps t in the label; role commits uploaded and fetched first. **Q0** as Q without that order.

Gates on deletes at hosts (must-not-hold and compaction): `none` (today's rules per side); `direct` no delete resting on a write by X or Y themselves; `neutral` must-not-hold also with every disputed write void; `touch` the body is not disputed and some reason holds whose write is not disputed; `exact` must-not-hold on both sides (two walks, the oracle); `aspect` no delete of a body on an aspect holding a disputed write or a reason write in Dd. Other candidates: (b) `ReupOnce`; (c) `Fork`; (d) `CoverOwn` (covers judged on the own side, ungated); `Bridge` (with the fork, a member also acts on clean bodies at the label it reads but does not act at).

Properties: `NoLoss` (invariant: a body that reached a host and some side keeps live has a copy somewhere), `Quiesce` (the host settles: no endless upload/delete loop), `Served` (a fresh node of a side some node is on finds at its labels every body that side keeps live and someone has), `Alike` (after its switches each node holds what a fresh node of its side reads), `PurgePrompt` (a purge both sides accept leaves every label). Weak fairness of honest steps; switches and compaction unfair.

## Results
TLC 2.19, 1 worker per run, shared 16-core box at load 20-40. Failed properties per cell (L NoLoss, Q Quiesce, S Served, A Alike, P PurgePrompt):

| mode | K | Z | F | C | P | Q | Q0 |
|---|---|---|---|---|---|---|---|
| none | LQSA | LQSA | QSA | L | ok | LQSA | LQSA |
| a-direct | ok | LQSA | ok | ok | ok | ok | L |
| a-neutral | ok | ok | QSA | ok | ok | LQSA | LQSA |
| a-touch | ok | ok | ok | ok | ok | ok | L |
| a-exact | ok | ok | ok | ok | ok | ok | L |
| a-aspect | ok | ok | ok | ok | P | ok | L |
| b | LSA | LSA | SA | LSA | ok | LSA | LSA |
| c | L | L | S | LS | SP | L | L |
| c+a-touch | S | S | S | S | SP | S | LS |
| c+a-touch+bridge | S | S | ok | S | ok | S | LS |
| d+a-touch | ok | ok | ok | L | ok | ok | L |

Named instances (`run.sh`): `kill_touch`, `purge_touch`, `place_touch` pass; `kill_none`, `grantee_direct`, `fall_neutral`, `purge_aspect`, `cover_own`, `reup_once`, `fork_split`, `place_order` fail as listed above (expected failures). Each 40 to 4,380 states, 1-9 s.

What the counterexamples are, and what follows from them: notes/owner-removal-plan.md, step 6.

## Not covered
Several hosts (a different race winner per host), several disputes, keep-at-least and `nobody`, live writes surviving a kill, covers resting on deaths that rest on a disputed write, inbox and deposits, the party erasing itself on a switch, stale views, clock skew.
