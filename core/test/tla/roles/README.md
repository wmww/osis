# Role walk (TLA+)
> Summary: TLC model of the role timeline (spec/permissions.md §1–§2, §5.1, §5.2): record edges (a first admin's, removable), actor holders, `until`, self-removals, explicit demotions with frontiers, the demoter's kept standing, several-edge removals, layer-2 content validity and the depth cap. Checks determinism (drop order), late writes of removed holders, demoter standing, admin content.

Files: `Roles.tla` (the model; `Scenario` picks a genesis and a menu of commits), `MC_*.cfg`, `AMBIGUITIES.md` (findings M1–M6). Unlike the other models, this one was written with the spec and checked against osis-perm where the text was subtle (AMBIGUITIES.md says where it follows osis-perm's reading).

## Shape
A state is a history: commits in generation order, each from the scenario's menu (at most once), with any ts from `TsSet` (so skew and backdating) and a frontier that is any subset of the commits generated before it, always including the author's chain certificates as an honest author holds them (`FrMode = "subset"`, `Certs`: commits setting the author's, A's or B's edges, and those of their authors; the author's own commits are left out, they never matter). Things: actor A, whose first admin is key actor n1, and actor B, whose first admin is A: their record edges (n1 on A, A on B) are in the edge state before every write and removable like any edge; B may be a holder of A, so B's admins reach A and roles are a fixpoint over the two. Roles none/read/write/admin, edges with `until`; no invites. Commit IDs order like generation. The invariants run the walk over the whole history (`W0`), from the record edges (the genesis commits set the rest), ordered by (ts, node, commit ID): restarts until D is stable, attribution by class (edge admin only), falls judged against the edge as restored plus the demoter's kept standing, frontier and same-commit coverage, self-removals audited by the class that allowed them (on the holder for one through an actor holder), layer 2 per content commit.

## Properties
- `DropOrderFree` (1): every order of finding the writes that add to D gives the same verdicts as the spec's restart at the first one. The walk is otherwise a function of the held set by construction (sorted by (ts, node, commit ID), D rebuilt from scratch), so this is the part of determinism that can fail.
- `LateEdge`, `LateContent` (2): a holder's edge write generated after a valid explicit demotion that took its class, and ordered before it, is not applied; its content generated after its newest demotion, with no regain and no re-grant, is invalid.
- `NoSelfDrop`, `StandingAudited` (3): no write is dropped by its author's own demotion; when a node demotes itself by removing actor B's admin edge, the next explicit removal of that edge by another node drops its uncovered edge-admin writes made before (its kept standing is audited).
- `ChainContent`, `DepthCap` (4): content by a node with admin at its point is valid unless a later demotion; nothing on a thing below `MaxDepth` record links is valid.
- `Probe*`: expected to fail; used by hand to show the instances reach drops, demotions, kept standings, invalid content and restarts.

## Instances and results
TLC 2.19, 8 workers, shared 16-core machine (wall clock; the record-edge model with every node's commits in frontier subsets runs 3-25x longer: `MC_until` 984 s, `MC_core` 80 s, `MC_depth` 270 s at 4 workers under load 15-40). 3 nodes; writes at ts 6, 8, 10 after genesis at 2 and 4. `run.sh small` runs `MC_core`, `MC_multi`, `MC_forge`, `MC_samets` and the two expected failures; `run.sh all roles/` runs every instance in under 2 min.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_core` | n2, n3 admins of A: mutual removals, a demotion, a grant on B through A's record edge, content; 3 free commits; drop order | all pass | 2,380 | 3 s |
| `MC_multi` | n2 admin of B, B admin of A: several-edge removal of B and n3 and the one-edge versions; drop order | all pass | 1,852 | 2 s |
| `MC_group` | as MC_multi's genesis plus n2 admin of A until 9: n2 removes B (before 9 an explicit write that demotes itself and keeps its standing, after it a self-removal), n1 rewrites the edge, n2 grants through B | all pass | 5,782 | 10 s |
| `MC_until` | n2 admin of A until 7, resets and re-grants, a self demotion | all pass | 107,959 | 37 s |
| `MC_depth` | `MaxDepth` 1: nothing on B valid | all pass | 31,660 | 14 s |
| `MC_samets` | n1 stamps two commits at one ts (a removal and a re-grant of n2); drop order | all pass | 8,971 | 11 s |
| `MC_forge` | removed admin backdates a write on its remover's edge (M1, fixed) | all pass | 580 | 2 s |
| `MC_first` | n2 removes the first admin n1's record edge on A; n1 removes n3 and re-grants itself, n3 removes n2, content by n1 (drop order not checked: it reaches M2) | all pass | 9,529 | 219 s |
| `MC_keepoff` | negative control: MC_group without the kept standing | **fails** StandingAudited (expected) | 719 | 2 s |
| `MC_sticky` | drop order (M2) | **fails** DropOrderFree (expected) | 822 | 3 s |

Probes (`Probe*`, run by hand) confirm that drops, layer-2 demotions, invalid content and kept standings (`MC_group`) all occur. Not reached: several drops in one walk outside `MC_sticky` (so `DropOrderFree` only bites there).

## Not covered
Invites and invite grants, links, more than two things or longer record chains (the depth cap is checked at 1), frontiers by counter range, pending commits, certificates and projections.
