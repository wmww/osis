# Rotation, claim steps, re-seal (TLA+)
> Summary: TLC model of read-role rotation for one actor and its label at one blind server (spec/crypto.md §3–§5, spec/sync.md §2/§5, spec/permissions.md §3–§4, spec/commits.md §2): forced and eager rotation, forks, removal carried in its rotation, grants, re-registration, opens by sync key and claims, claim-set drops, stranded heartbeats (also on a refused claim), deposit-seed refresh, re-seal by inbox after a full pass, member peers. Written from spec/ alone.

Files: `Rotation.tla` (the model; constants come straight from each `.cfg`), `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
`../run.sh small` (CI-sized instances of both models) or `../run.sh all`; it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config MC_live.cfg Rotation
```

## Properties
Invariants: `NoLeak` (crypto §4 covers rule: content written while the writer knew of M's departure is never readable by M), `DepartedLocked` (permissions §3: a departed member never holds an epoch whose rotation did not box it). Temporal, under weak fairness of honest steps: `CurrentOpens` (every current member eventually holds every current epoch), `ReadsAll` (... and every epoch content was written under, older ones by history boxes). "A writer never encrypts under a superseded epoch after it holds the rotation" holds by construction (`EncEp` takes the newest held current epoch) and is not a separate check.

## Instances and results
TLC 2.19, 1 worker, on a shared, heavily loaded 4-core machine (times are wall clock). Admins a1, a2; a1 may remove m1. `run.sh` lists the expected failures.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_live.cfg` | reader m1; removal (1 rotation), 1 write, log order | all pass | 2,198 | 2 s |
| `MC_grant.cfg` | reader m2 granted later (racing a rotation, or after it), 1 rotation, 1 write | all pass | 21,909 | 1 min |
| `MC_drop.cfg` | reader m1; 2 rotations, no removal, claim sets may drop | all pass | 426,171 | 21 min |
| `MC_drop_refresh.cfg` | as MC_drop, every rotation refreshes the deposit seed | **fails** `CurrentOpens` (residue 2, expected) | 675 | 2 s |
| `MC_safety.cfg` | removal, 2 rotations, 1 write, log order; invariants only | pass | 550,984 | 4 min |
| `MC_reorder.cfg` | as MC_safety, any order, member peers | **fails** `DepartedLocked` (residue 1 without a fork, expected) | 47,541 | 7 s |
| `MC_hist.cfg` | as MC_safety, history boxes carry every held secret | **fails** `DepartedLocked` (R9, expected) | 19,112 | 5 s |
| `MC_fork.cfg` | 2 rotations (forks), no removal, 1 write | all pass | 471,416 | 15 min |
| `MC_fork_reorder.cfg` | removal, 3 rotations (fork), 1 write, any order, peers | **fails** `DepartedLocked` (residue 1, expected) | 30,023 | 3 s |

`run.sh small` runs `MC_live.cfg` and `MC_grant.cfg`.

## Not covered
Write and admin rotation, keysets and departures inside a member, demotion and `until`, several servers or branches of the step tree, steps without rotation, entry boxes and key-actor readers, `/label` records, `MEMBERSHIP_KEEP` compaction of steps in `/label` and of rotation commits (`/secrets` snapshots).
