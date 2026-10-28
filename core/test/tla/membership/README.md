# Membership walk and tenure ledger (TLA+)
> Summary: TLC model of the membership timeline and roster snapshots (spec/permissions.md §1–§2, §5.1, §5.2, §6): owner chains, actor members, `until`, self-removals, explicit demotions with frontiers, the demoter's kept standing, several-edge removals, layer-2 content validity, the depth cap, ledger production and its replay. Checks determinism (drop order), snapshot neutrality, late writes of removed members, demoter standing, owner-chain scope.

Files: `Membership.tla` (the model; `Scenario` picks a genesis and a menu of commits), `MC_*.cfg`, `AMBIGUITIES.md` (findings M1–M10). Unlike the other models, this one was written with the spec and checked against osis-perm where the text was subtle (AMBIGUITIES.md says where it follows osis-perm's reading).

## Shape
A state is a history: commits in generation order, each from the scenario's menu (at most once), with any ts from `TsSet` (so skew and backdating) and a frontier that is any subset of the commits generated before it, always including the author's chain certificates as an honest author holds them (`FrMode = "subset"`, `Certs`: commits setting the author's or B's edges, and those of their authors; the author's own and node 1's commits are left out, they never matter). Things: actor A owned by key actor n1, actor B owned by A; B may be a member of A, so B's admins reach A. Roles none/read/write/admin, edges with `until`; no invites. Commit IDs order like generation. The invariants run the walk over the whole history (`W0`): restarts until D is stable, attribution by class, falls judged against the edge as restored plus the demoter's kept standing, frontier and same-commit coverage, self-removals never audited, layer 2 per content commit. `WithSnap(N, s, au)` produces the roster and ledger of N at ts `s` from `W0` (what an owner-chain author holding everything writes), replays them as virtual writes (an entry with a frontier is an explicit demotion by its key's node), walks again with N's earlier edge writes ignored, and compares.

## Properties
- `DropOrderFree` (1): every order of finding the writes that add to D gives the same verdicts as the spec's restart at the first one. The walk is otherwise a function of the held set by construction (sorted by (ts, node, commit ID), D rebuilt from scratch), so this is the part of determinism that can fail.
- `Neutral` (2): for each snapshot point, author and thing in `SnapThings`, the walk with the snapshot as epoch start gives the same applied edge writes (those not ignored), valid content and end roles as without it (§6). A snapshot whose author lacks owner-chain authority, or that is dropped, in the walk where D settles (its roster applies meanwhile) is not an epoch start and is not compared.
- `LateEdge`, `LateContent` (3): a member's edge write generated after a valid explicit demotion that took its class, and ordered before it, is not applied; its content generated after its newest demotion, with no regain and no re-grant, is invalid.
- `NoSelfDrop`, `StandingAudited` (4): no write is dropped by its author's own demotion; when a node demotes itself by removing actor B's admin edge, the next explicit removal of that edge by another node drops its uncovered edge-admin writes made before (its kept standing is audited).
- `ChainContent`, `DepthCap` (5): content by an owner-chain node is valid unless a later demotion; nothing on a thing below `MaxDepth` owner links is valid.
- `Probe*`: expected to fail; used by hand to show the instances reach drops, demotions, ledger entries with frontiers, applied snapshots.

## Instances and results
TLC 2.19, 1 worker, shared 16-core machine at load ~15–20 (wall clock). 3 nodes; writes at ts 6, 8, 10 after genesis at 2 and 4; snapshots at ts 3–11. `run.sh small` runs `MC_core`, `MC_multi`, `MC_forge`, `MC_samets` and the three expected failures (about 30 s at 4 workers).

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_core` | n2, n3 admins of A: mutual removals, a demotion, a chain grant on B, content; 3 free commits; drop order | all pass | 2,380 | 9 s |
| `MC_multi` | n2 admin of B, B admin of A: several-edge removal of B and n3 and the one-edge versions; snapshots of A; drop order | all pass | 1,852 | 18 s |
| `MC_group` | as MC_multi's genesis: n2 removes B (demotes itself, keeps its standing), n1 rewrites the edge, n2 grants through B; snapshots of A | all pass | 5,782 | 2 min |
| `MC_snapA` | n2 admin of A, 4 free commits incl. self-demotion and removal; snapshots of A by n1 | all pass | 72,316 | 9 min |
| `MC_snapB` | snapshots of B by n1 or n2 (rejected after n2's removal) | all pass | 54,436 | 12 min |
| `MC_until` | n2 admin of A until 7, resets and re-grants (audit-only entries); snapshots of A | all pass | 107,959 | 10 min |
| `MC_depth` | `MaxDepth` 1: nothing on B valid; snapshots of A | all pass | 31,660 | 2 min |
| `MC_keepoff` | negative control: MC_group without the kept standing | **fails** StandingAudited (expected) | 443 | 2 s |
| `MC_sticky` | drop order (M2) | **fails** DropOrderFree (expected) | 791 | 1 s |
| `MC_sticky_snap` | a snapshot repairs a sticky drop (M2) | **fails** Neutral (expected) | 710 | 2 s |
| `MC_forge` | removed admin backdates a write on its remover's edge (M1, fixed) | all pass | 580 | 3 s |
| `MC_samets` | n1 stamps two commits at one ts (M3, fixed) | all pass | 8,971 | 13 s (4 workers) |

`MC_samets` trace (M3, before the fix): n1 grants n2 admin of A; n2 grants n3 admin on B at ts 6; n1 removes n2 at ts 8 (frontier empty, so the grant on B drops) and re-grants n2 at ts 8 in another commit. With keys (8, n1) the tenure ended and the roster edge started at one key, the replay saw no demotion, and a snapshot of A after both revived the grant. Keys now carry the commit ID (<<ts, node, id>>; a virtual write sits just after the commit its key names, as spec §6 places it), so the replay demotes at the first commit and re-grants at the second.

Probes (`Probe*`, run by hand) confirm that drops, layer-2 demotions, invalid content, ledger entries with frontiers, audit-only entries (`MC_until`), applied snapshots whose ledger drops a write on B (`MC_snapA`) and kept standings (`MC_group`) all occur. Not reached: several drops in one walk outside `MC_sticky` (so `DropOrderFree` only bites there).

## Not covered
Invites and invite grants, links, read-level tenures, a second snapshot (carried-forward ledger), epoch-start rounds and exclusions (spec §6: `WithSnap` makes one snapshot the start and judges it in its own settled walk), more than two things or longer owner chains (the depth cap is checked at 1), frontiers by counter range, pending commits, certificates and projections.
