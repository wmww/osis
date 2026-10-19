# Rotation, claim steps, re-seal (TLA+)
> Summary: TLC model of read-role rotation for one actor and its label at one blind server (spec/crypto.md §4–§5, spec/sync.md §2/§5, spec/permissions.md §3–§4): forced and eager rotation, forks, removal, re-registration, opens by sync key and claims, claim-set drops, stranded heartbeats, re-seal by inbox. Written from spec/ alone.

Files: `Rotation.tla` (the model; constants come straight from each `.cfg`), `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
TLC is not vendored. Download it once (not into the repo):
```
mkdir -p ~/.cache/tla
curl -sSL -o ~/.cache/tla/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```
Then, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config MC_live.cfg Rotation
```

## Properties
Invariants: `NoLeak` (crypto §4 covers rule: content written while the writer knew of M's departure is never readable by M), `DepartedLocked` (permissions §3: a departed member never holds an epoch whose rotation did not box it). Temporal, under weak fairness of honest steps: `CurrentOpens` (every current member eventually holds every current epoch), `ReadsAll` (... and every epoch content was written under). "A writer never encrypts under a superseded epoch after it holds the rotation" holds by construction (`EncEp` takes the newest held current epoch) and is not a separate check.

## Instances and results
TLC 2.19, 1 worker, on a shared loaded 4-core machine. All instances: admins a1, a2 and reader m1; a1 may remove m1.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_live.cfg` | 1 rotation, removal, 1 write, log order kept | all pass | 13,894 | 10 s |
| `MC_safety.cfg` | 2 rotations, removal, 1 write, log order kept; invariants only | pass | 4,917,682 | 19 min |
| `MC_reorder.cfg` | as MC_safety, any delivery order | **fails** `DepartedLocked`, `NoLeak` (R1), 9-state trace | 5,450 (partial) | 1 s |
| `MC_drop.cfg` | 2 rotations, no removal, claim sets may drop | **fails** `CurrentOpens` (R2), 8-state trace | 5,338 (partial) | 3 s |
| `MC_fork.cfg` | 2 rotations (forks), no removal, 1 write | all pass | 458,920 | 15 min |

The smallest clean instance for CI is `MC_live.cfg`.

## Not covered
Write and admin rotation, keysets and departures inside a member, grants after epoch 0 (so R3 is unchecked), demotion and `until`, several servers or branches of the step tree, steps without rotation, entry boxes and key-actor readers, `/label` records, `MEMBERSHIP_KEEP` compaction of steps in `/label`.
