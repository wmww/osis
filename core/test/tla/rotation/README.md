# Rotation, claim steps, re-seal (TLA+)
> Summary: TLC model of read-role rotation for one actor and its label at one host (spec/crypto.md §3–§5, spec/sync.md §2/§5, spec/permissions.md §3–§4, spec/commits.md §2): epochs established by names (the removals, the departures from the holder actor and its keyset epoch a rotation's rotator held), a removal withheld forever from one admin, a holder actor whose admin device leaves it and then forges its keyset, forced and eager rotation, forks, removal carried in its rotation, grants, re-registration after uploading the rotation chain, opens by sync key and claims, claim-set drops, stranded heartbeats (also on a refused claim), deposit-seed refresh, re-seal after a complete pass (by inbox and under the label), rotation by inbox to holders without a box at the epoch before, per-node box knowledge, co-reader peers, planted boxes (reading-only secrets). Written from spec/ alone.

Files: `Rotation.tla` (the model; constants come straight from each `.cfg`), `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
`../run.sh small` (CI-sized instances of both models) or `../run.sh all`; it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config MC_live.cfg Rotation
```

## Properties
Invariants: `NoLeak` (crypto §4 covers rule: content written while the writer knew of M's departure is never readable by M), `DepartedLocked` (permissions §3: a departed holder never holds an epoch whose rotation did not box it), `DevLocked` and `DevNoLeak` (the same for device d that left holder actor g: it never opens an epoch whose rotator knew d left (held R_P), nor content written by a writer that knew it), `NoPlantedKey` (crypto §4: a secret learned only from a pending or invalid commit is never encrypted under: no wrap, box, history box, step or heartbeat under it). `NoPlantedKey` holds because `Enc(x)` (what x encrypts under) is `sec[x]`; negative control: with `Enc(x) == sec[x] \cup fsec[x]` (the text before the edit) `MC_plant` fails in 4 states (a grantee heartbeats under a planted secret before its grant box arrives; AMBIGUITIES.md R15). Temporal, under weak fairness of honest steps: `CurrentOpens` (every current holder eventually holds every current epoch), `ReadsAll` (... and every epoch content was written under, older ones by history boxes). "A writer never encrypts under a superseded epoch after it holds the rotation" holds by construction (`EncEp` takes the newest held current epoch) and is not a separate check.

## Instances and results
TLC 2.19, 1 worker, on a shared 4-core machine at load ~10 (two compiling agents and another TLC run beside; times are wall clock). Admins a1, a2; a1 may remove m1. `run.sh` lists the expected failures.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_live.cfg` | reader m1; removal (1 rotation), 1 write, log order | all pass | 64 | 3 s |
| `MC_grant.cfg` | reader m2 granted later (racing a rotation, or after it), 1 rotation, 1 write | all pass | 2,962 | 27 s |
| `MC_plant.cfg` | as MC_grant, a non-holder plants one box; invariants only | pass | 12,694 | 15 s |
| `MC_drop.cfg` | reader m1; 2 rotations, no removal, claim sets may drop | all pass | 9,653 | 3 min |
| `MC_drop_refresh.cfg` | as MC_drop, every rotation refreshes the deposit seed | **fails** `CurrentOpens` (residue 2, expected) | 475 | 7 s |
| `MC_safety.cfg` | removal, 2 rotations, 1 write, log order; invariants only | pass | 2,509 | 2 s |
| `MC_reorder.cfg` | as MC_safety, any order, co-reader peers (was residue 1 without a fork) | pass | 29,809 | 14 s |
| `MC_grant_remove.cfg` | reader m2 granted later, removal of m1, 2 rotations, no write, log order; invariants only | pass | 6,411,278 | 35 min |
| `MC_fork.cfg` | 2 rotations (forks), no removal, 1 write | all pass | 1,060 | 2 s |
| `MC_fork_reorder.cfg` | removal, 3 rotations (fork), 1 write, any order, peers (was residue 1) | pass | 2,614,146 | 10 min |
| `MC_withhold.cfg` | as MC_fork_reorder in log order, the host withholding the removal from a2 forever (its log skips it); invariants only | pass | 2,859,816 | 19 min |
| `MC_names_own.cfg` | as MC_withhold without the write, each rotation naming only itself (negative control) | **fails** `DepartedLocked` (expected) | 14,466 | 6 s |
| `MC_keyset.cfg` | holder actor g, its device d leaves (g's keyset 0 to 1), a2 never learns it; 2 rotations, 1 write; invariants only | pass | 4,310 | 7 s |
| `MC_keyset_nonames.cfg` | as MC_keyset without keyset names, a2 may get a roster snapshot of g after d left (negative control) | **fails** `DevLocked` (expected) | 2,485 | 1 s |
| `MC_keyset_forge.cfg` | as MC_keyset, d an admin of g forges g's keyset after leaving it, a2 may get a roster snapshot of g after R_P; no write | pass | 23,627 | 3 s |
| `MC_keyset_forge_rot.cfg` | as MC_keyset_forge, g may also be rotated again after R_P | pass | 350,229 | 210 s (2 workers, loaded) |
| `MC_keyset_forge_nogroup.cfg` | as MC_keyset_forge without names of departures from g (negative control) | **fails** `DevLocked` (expected) | 2,730 | 2 s |
| `MC_keyset_forge_commit.cfg` | g rotated again and forged, keyset names met only by the named keyset's own commit, no names of departures from g (negative control) | **fails** `DevLocked` (expected) | 45,747 | 3 s |
| `MC_keyset_forge_write.cfg` | g rotated again and forged, one write | **fails** `DevNoLeak` (expected, AMBIGUITIES.md R18) | 97,665 | 8 s |

Names rerun (issues/epoch-establishment-redesign.md step 4; `Est` was the settled-chain rule: an epoch counted once its rotation commit was held and every epoch it superseded was established). TLC 2.19, 4 workers, load 50-55; table rows above updated where the count changed (`MC_grant_remove` again 6,411,278 states, 60 min at that load). The any-order version of `MC_withhold` grew past 5 million distinct states with a million queued and was stopped: withholding lets a2 finish its passes early, so its re-seals fire in many more interleavings. Negative-control traces: `MC_names_own` (a2 withheld e2, a1's removal of m1; a1 merges e1 and e2 into e3, wrapped under a2's e1; e3 names nothing, so a2 establishes it, sees m1 a holder missing a box there and re-seals e3 to it); `MC_keyset_nonames` (d leaves g; a1 learns keyset 1, rotates to e1 boxing g at 1; a2, never learning it, applies e1, establishes it and rotates to e2 boxing g at 0 with e1 in the history box, which d opens).

`run.sh small` runs `MC_live`, `MC_grant`, `MC_plant`, `MC_safety`, `MC_fork`, `MC_names_own`, `MC_keyset`, `MC_keyset_nonames` and the `MC_keyset_forge*` instances but `_rot`.

Forged holder keysets (AMBIGUITIES.md R17, R18; TLC 2.19, 2 workers, shared box): a removed admin d of holder actor g writes g's keyset where its removal is withheld. Rows above. Traces: `MC_keyset_forge_nogroup` (a1 boxes g at keyset 1 naming it; d writes 3 listing 1; a2, lacking R_P, holds 3 valid, establishes a1's epoch and rotates boxing g at 3 with it in its history box); `MC_keyset_forge_commit` (a1 holds 2, names it; a2 holds 2 and 3, establishes a1's epoch, boxes g at 3). `MC_grant_remove` is over the ~20 min budget on this loaded machine (the label-placed re-seals add their box records to the state; it was 1.76 million states before); it is kept because it is the only instance where a re-seal sits next to a removal.

Hardening rerun: re-seals are placed under the label as well as sent by inbox, each node judges boxes by what it has applied and read (`Holders`), a rotation goes by inbox to a boxed holder without a box at the epoch before, and a planted box gives a reading-only secret. Every result is unchanged; probes (throwaway invariants) confirm that re-seals fire and are read by the other admin in `MC_grant`, and that rotation by inbox fires with a grant and two rotations.

Since registration waits for the rotation chain to be uploaded, the interleavings in which a step outran its rotation commit (and the stranded heartbeats and re-seals they caused) are gone, which is why most instances shrank by two orders of magnitude. Re-seals fire in `MC_drop`, `MC_grant` and `MC_grant_remove` (checked with an action property) but never in `MC_safety`, `MC_reorder` or `MC_fork_reorder`: with established epochs nothing triggers one there, so those instances check that no re-seal misfires rather than that a firing one is safe; `MC_grant_remove` covers a re-seal next to a removal (in log order; an any-order version passed 7 million states in 25 minutes and was stopped).

## Not covered
Write and admin rotation, holder actors beyond one group with one leaving device (no nested holders, no keyset fork, the group's honest keyset changes made outside the model), epoch starts (roster snapshots) of the rotated actor, forged history entries, invalid rotation commits, demotion and `until`, several hosts or branches of the step tree, steps without rotation, entry boxes and key-actor readers, `label.0` records, `ROLE_KEEP` compaction of steps in `label.0` and of rotation commits (`secrets.0` snapshots, so snapshot-established epochs and the post-compaction residue of notes/sync.md Limits).
