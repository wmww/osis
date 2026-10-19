# Rotation, claim steps, re-seal (TLA+)
> Summary: TLC model of read-role rotation for one actor and its label at one blind server (spec/crypto.md §3–§5, spec/sync.md §2/§5, spec/permissions.md §3–§4, spec/commits.md §2): established epochs, forced and eager rotation, forks, removal carried in its rotation, grants, re-registration after uploading the rotation chain, opens by sync key and claims, claim-set drops, stranded heartbeats (also on a refused claim), deposit-seed refresh, re-seal by inbox after a complete pass, member peers. Written from spec/ alone.

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
TLC 2.19, 1 worker, on a shared, heavily loaded 4-core machine (times are wall clock, often with another TLC run beside). Admins a1, a2; a1 may remove m1. `run.sh` lists the expected failures.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_live.cfg` | reader m1; removal (1 rotation), 1 write, log order | all pass | 64 | 4 s |
| `MC_grant.cfg` | reader m2 granted later (racing a rotation, or after it), 1 rotation, 1 write | all pass | 4,283 | 20 s |
| `MC_drop.cfg` | reader m1; 2 rotations, no removal, claim sets may drop | all pass | 2,035 | 21 s |
| `MC_drop_refresh.cfg` | as MC_drop, every rotation refreshes the deposit seed | **fails** `CurrentOpens` (residue 2, expected) | 663 | 11 s |
| `MC_safety.cfg` | removal, 2 rotations, 1 write, log order; invariants only | pass | 2,509 | 6 s |
| `MC_reorder.cfg` | as MC_safety, any order, member peers (was residue 1 without a fork) | pass | 29,809 | 11 s |
| `MC_grant_remove.cfg` | reader m2 granted later, removal of m1, 2 rotations, no write, log order; invariants only | pass | 1,762,345 | 10 min |
| `MC_fork.cfg` | 2 rotations (forks), no removal, 1 write | all pass | 1,060 | 3 s |
| `MC_fork_reorder.cfg` | removal, 3 rotations (fork), 1 write, any order, peers (was residue 1) | pass | 2,607,671 | 21 min |

`run.sh small` runs `MC_live`, `MC_grant`, `MC_safety` and `MC_fork`.

Since registration waits for the rotation chain to be uploaded, the interleavings in which a step outran its rotation commit (and the stranded heartbeats and re-seals they caused) are gone, which is why most instances shrank by two orders of magnitude. Re-seals fire in `MC_drop`, `MC_grant` and `MC_grant_remove` (checked with an action property) but never in `MC_safety`, `MC_reorder` or `MC_fork_reorder`: with established epochs nothing triggers one there, so those instances check that no re-seal misfires rather than that a firing one is safe; `MC_grant_remove` covers a re-seal next to a removal (in log order; an any-order version passed 7 million states in 25 minutes and was stopped).

## Not covered
Write and admin rotation, keysets and departures inside a member, demotion and `until`, several servers or branches of the step tree, steps without rotation, entry boxes and key-actor readers, `/label` records, `MEMBERSHIP_KEEP` compaction of steps in `/label` and of rotation commits (`/secrets` snapshots, so snapshot-established epochs and the post-compaction residue of notes/sync.md Limits).
