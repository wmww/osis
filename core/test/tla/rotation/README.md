# Rotation, claim steps, re-seal (TLA+)
> Summary: TLC model of read-role rotation for one actor and its label at one host (spec/crypto.md §3–§5, spec/sync.md §2/§5, spec/permissions.md §3–§4, spec/commits.md §2): epochs established by names (the removals, the departures from the holder actor and its keyset epoch a rotation's rotator held), frozen coverage (an epoch covers exactly the departures it names; boxes to the holder actor carry their writer's names) against the box-inspection covers rule, a removal withheld forever from one admin, a holder actor whose admin device leaves it (the removal's roles and keys parts arriving apart), then forges its keyset or is forked by an admin that has not seen it, granted after a rotation (the grant reaching an admin as its edge alone, a projection), forced and eager rotation, forks, removal carried in its rotation, grants, re-registration after uploading the rotation chain, opens by sync key and claims, claim-set drops, stranded heartbeats (also on a refused claim), deposit-seed refresh, re-seal after a complete pass (by inbox and under the label), rotation by inbox to holders without a box at the epoch before, per-node box knowledge, co-reader peers, planted boxes (reading-only secrets). Written from spec/ alone.

Files: `Rotation.tla` (the model; constants come straight from each `.cfg`), `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings). `Depth0.tla` is a separate model of depth-0 sealing (section at the end).

## Run
`../run.sh small` (CI-sized instances of both models) or `../run.sh all`; it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config MC_live.cfg Rotation
```

## Properties
Invariants: `NoLeak` (crypto §4 covers rule: content written while the writer knew of M's departure is never readable by M), `DepartedLocked` (permissions §3: a departed holder never holds an epoch whose rotation did not box it; a property of the box rule only, AMBIGUITIES.md R19), `DevLocked` and `DevNoLeak` (the same for device d that left holder actor g: it never opens an epoch whose rotator knew d left (held R_P), nor content written by a writer that knew it), `DevGranted` (g granted once, by a granter that held R_P: d, gone before g held a role, opens nothing of A), `NoPlantedKey` (crypto §4: a secret learned only from a pending or invalid commit is never encrypted under: no wrap, box, history box, step or heartbeat under it). `NoPlantedKey` holds because `Enc(x)` (what x encrypts under) is `sec[x]`; negative control: with `Enc(x) == sec[x] \cup fsec[x]` (the text before the edit) `MC_plant` fails in 4 states (a grantee heartbeats under a planted secret before its grant box arrives; AMBIGUITIES.md R15). Temporal, under weak fairness of honest steps: `CurrentOpens` (every current holder eventually holds every current epoch), `ReadsAll` (... and every epoch content was written under, older ones by history boxes). "A writer never encrypts under a superseded epoch after it holds the rotation" holds by construction (`EncEp` takes the newest held current epoch) and is not a separate check.

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
| `MC_keyset_forge_write.cfg` | g rotated again and forged, one write | pass under frozen coverage (box rule: fails `DevNoLeak`, AMBIGUITIES.md R18) | 410,060 | 9 min |
| `MC_c2_box.cfg` | study C2, box rule: m2 granted, removed by a1 as a fork of a2's e1; 1 write | **fails** `NoLeak` (expected, R19) | 12,923 | 2 s |
| `MC_c2.cfg` | as MC_c2_box, frozen coverage | pass (review rerun, 4 workers, load 10-25) | 1,440,841 | 532 s |
| `MC_c2_boxcovers.cfg` | as MC_c2, no box counts as covering (negative control) | **fails** `NoLeak` (expected) | 13,363 | 42 s |
| `MC_c1_box.cfg` | study C1, box rule: R_P's parts apart (a2 never the roles part), g forked by an ignorant admin; 1 write | **fails** `DevNoLeak` (expected) | 133,272 | 5.5 min |
| `MC_c1.cfg` | as MC_c1_box, frozen coverage | no violation (unfinished, stopped) | 997,589+ | 60 min |
| `MC_c1f_box.cfg` | study C1', box rule: as MC_c1_box with d's forged keyset instead of the fork | **fails** `DevNoLeak` (expected) | 46,419 | 94 s |
| `MC_c1f.cfg` | as MC_c1f_box, frozen coverage | no violation (unfinished, stopped) | 985,456+ | 60 min |
| `MC_c3_box.cfg` | study C3, box rule: g granted after d left it, a1 knowing; no write | **fails** `DevGranted` (expected) | 5,327 | 36 s |
| `MC_c3_current.cfg` | C3, frozen, the study's names-of-current-boxes rule | **fails** `DevGranted` (expected, R20) | 2,194 | 55 s |
| `MC_c3_boxed.cfg` | as MC_c3_current, grants leaving g out refused | **fails** `DevGranted` (expected, R20) | 10,812 | 56 s |
| `MC_c3.cfg` | C3, frozen, names tied to the grant | no violation (unfinished, stopped; review rerun, 4 workers, load 25-40: depth 21, 10.8M queued and growing) | 29,048,762+ | 63 min |
| `MC_c3_lean.cfg` | as MC_c3 without g's fork | no violation (unfinished, stopped) | 889,765+ | 15 min |
| `MC_c3_nonames.cfg` | as MC_c3, grants carry no names (negative control) | **fails** `DevGranted` (expected) | 5,325 | 34 s |
| `MC_c3_proj.cfg` | as MC_c3_lean with one rotation, a2 may hold a1's grant of g as its edge alone (`Proj`, `LearnEdge`: the boxes never read); holding no box to g carrying names (`Free`: a grant's read, a free rotation's applied; a bound seal's carry none) it seals g only to the keyset g's roster entry names (`rk`), held valid, or leaves g out | pass (a probe invariant confirmed a2 boxes g at keyset 1 through it); with two rotations no violation in 4.5M states, 15 min, stopped; under the sealer-names rule (`Free`, `rk`) 138,141 states, 35 s | 131,747 | 8 s (4 workers) |
| `MC_c3_proj_free.cfg` | as MC_c3_proj, a2 seals g at its own newest keyset (negative control) | **fails** `DevGranted` (expected) | 1,802 | 2 s |
| `MC_c3_proj_bad.cfg` | as MC_c3_proj, and a second edge write of g naming a keyset nobody holds reaches a2 (`BadEdge`): bound to it, a2 leaves g out until a1's free box reaches it (safety only: `CurrentOpens` would need `MaxE` 2, a1 must rotate before re-sealing g) | pass | 297,474 | 30 s (4 workers) |

Names rerun (issues/epoch-establishment-redesign.md step 4; `Est` was the settled-chain rule: an epoch counted once its rotation commit was held and every epoch it superseded was established). TLC 2.19, 4 workers, load 50-55; table rows above updated where the count changed (`MC_grant_remove` again 6,411,278 states, 60 min at that load). The any-order version of `MC_withhold` grew past 5 million distinct states with a million queued and was stopped: withholding lets a2 finish its passes early, so its re-seals fire in many more interleavings. Negative-control traces: `MC_names_own` (a2 withheld e2, a1's removal of m1; a1 merges e1 and e2 into e3, wrapped under a2's e1; e3 names nothing, so a2 establishes it, sees m1 a holder missing a box there and re-seals e3 to it); `MC_keyset_nonames` (d leaves g; a1 learns keyset 1, rotates to e1 boxing g at 1; a2, never learning it, applies e1, establishes it and rotates to e2 boxing g at 0 with e1 in the history box, which d opens).

Keyset descent (notes/roster-names.md; constants `Descent`, `Sigs`): a keyset carries a signature under the delete key of each superseded epoch whose secret its writer held (`Desc`: d's forgery 3 descends from 0 only, the ignorant fork 4 from 0, 2 from 0 and 1), rotations name no departure from g unless they leave g out (`ng`, the anchors carried forward in `nk`), and a boxer of g seals only to the newest held valid keyset that is or descends from every anchor (`Anchors`, `Cand`), judged by descent from R_P's keyset (`Keeps`); d's departure is covered where the box to g names such a keyset. TLC 2.19, 2-3 workers, load 35-45:

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `MC_desc_keyset.cfg` | as MC_keyset without names of departures from g | pass | 4,310 | 10 s |
| `MC_desc_forge.cfg` | as MC_keyset_forge without names of departures from g: the forgery lists 1 unsigned | pass | 17,901 | 25 s |
| `MC_desc_forge_nosig.cfg` | negative control: descent read from the listed epochs alone | **fails** `DevLocked` (expected: a2 rotates boxing g at 3) | 912+ | 10 s |
| `MC_desc_forge_rot.cfg` | as MC_keyset_forge_rot | pass | 255,665 | 81 s (3 workers) |
| `MC_desc_c1.cfg` | C1: a2 holds the fork 4 and keyset 1, boxes g at 1 | no violation (unfinished, stopped; queue growing, as MC_c1) | 966,281+ | 18 min (4 workers) |
| `MC_desc_c1f.cfg` | C1' | no violation (unfinished, stopped) | 887,168+ | 18 min (4 workers) |
| `MC_desc_c3.cfg` | C3 with the fork and the forgery, grants carrying the keyset name alone | no violation (unfinished, stopped; 2.3M queued, as MC_c3) | 4,224,625+ | 18 min (4 workers) |

`run.sh small` runs `MC_live`, `MC_grant`, `MC_plant`, `MC_safety`, `MC_fork`, `MC_names_own`, `MC_keyset`, `MC_keyset_nonames`, the `MC_keyset_forge*` instances but `_rot`, and `MC_desc_keyset`, `MC_desc_forge` and `MC_desc_forge_nosig`.

Forged holder keysets (AMBIGUITIES.md R17, R18; TLC 2.19, 2 workers, shared box): a removed admin d of holder actor g writes g's keyset where its removal is withheld. Rows above. Traces: `MC_keyset_forge_nogroup` (a1 boxes g at keyset 1 naming it; d writes 3 listing 1; a2, lacking R_P, holds 3 valid, establishes a1's epoch and rotates boxing g at 3 with it in its history box); `MC_keyset_forge_commit` (a1 holds 2, names it; a2 holds 2 and 3, establishes a1's epoch, boxes g at 3). `MC_grant_remove` is over the ~20 min budget on this loaded machine (the label-placed re-seals add their box records to the state; it was 1.76 million states before); it is kept because it is the only instance where a re-seal sits next to a removal.

Hardening rerun: re-seals are placed under the label as well as sent by inbox, each node judges boxes by what it has applied and read (`Holders`), a rotation goes by inbox to a boxed holder without a box at the epoch before, and a planted box gives a reading-only secret. Every result is unchanged; probes (throwaway invariants) confirm that re-seals fire and are read by the other admin in `MC_grant`, and that rotation by inbox fires with a grant and two rotations.

Frozen coverage rerun (AMBIGUITIES.md R19, R20; TLC 2.19, 2 workers, load 40-75, wall clock): every cfg now sets `Frozen = TRUE` but the `_box` ones. Rerun under it: `MC_live`, `MC_grant`, `MC_plant`, `MC_safety`, `MC_fork`, `MC_keyset`, `MC_keyset_forge` pass with the state counts above; `MC_names_own` (`DepartedLocked`), `MC_keyset_nonames`, `MC_keyset_forge_nogroup`, `MC_keyset_forge_commit` (`DevLocked`) fail as before. Not rerun under it: `MC_drop`, `MC_drop_refresh`, `MC_reorder`, `MC_grant_remove`, `MC_fork_reorder`, `MC_withhold`, `MC_keyset_forge_rot`. The frozen C1/C1'/C2 instances have MaxE = 2 (no rotation left after the trap: they check that nobody writes under the epoch); with MaxE = 3 they passed 1.8-5.7 million distinct states, unfinished.

Since registration waits for the rotation chain to be uploaded, the interleavings in which a step outran its rotation commit (and the stranded heartbeats and re-seals they caused) are gone, which is why most instances shrank by two orders of magnitude. Re-seals fire in `MC_drop`, `MC_grant` and `MC_grant_remove` (checked with an action property) but never in `MC_safety`, `MC_reorder` or `MC_fork_reorder`: with established epochs nothing triggers one there, so those instances check that no re-seal misfires rather than that a firing one is safe; `MC_grant_remove` covers a re-seal next to a removal (in log order; an any-order version passed 7 million states in 25 minutes and was stopped).

## Not covered
Write and admin rotation, holder actors beyond one group with one leaving device (no nested holders, the group's honest keyset changes made outside the model), a grant's edge without its box (one record), the compaction residual of the study (a snapshot of g meeting the name with g forked: `GSnap` with "fork" is in no cfg), epoch starts (roster snapshots) of the rotated actor, forged history entries, invalid rotation commits, demotion and `until`, several hosts or branches of the step tree, steps without rotation, entry boxes and key-actor readers, `label.0` records, `ROLE_KEEP` compaction of steps in `label.0` and of rotation commits (`secrets.0` snapshots, so snapshot-established epochs and the post-compaction residue of notes/sync.md Limits).

## Depth0.tla: depth-0 sealing (notes/keys-requirements-study.md §4)
Several actors and holder actors, read role only, an actor's keyset = its read epoch; crypto as access (a node's secrets: the closure over boxes and history boxes of the commits it holds; a removed device's: over every box ever written); any delivery order; ignorant forks, unprompted rotations and one forged keyset as one-shot steps; A's own departures by frozen coverage (no establishment, hosts or claims: Rotation.tla's). Constants select the rule variants (`Stale`, `Anchor`, `Merge`, `LeaveOut`, `CycleCheck`, `Rejoin`; for rule 4 `Grants`, `Hidden`, `Taint`, `MaxBlind`); instances are defined in `Depth0MC.tla` (a `.cfg` cannot write tuples), so run with module `Depth0MC`:
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 4 \
  -metadir /tmp/tlc-states -config D0_cyc.cfg Depth0MC
```
Properties: `NoLeakDirect`, `NoLeakMember`, `NoLeakMemberAll` (invariants), `Excludes`, `CurrentOpens`, `ReadsAll`, `Settles` (fairness of learning, forced rotation, re-seal). The rule-4 instances (`D0_nc*`, last table) are in run.sh; the rows above record the candidates that failed. TLC 2.19, 3-4 workers, a shared box at load 40-100 (wall clock).

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `D0_member` | A {a1, M}, M {m1, m2, D}; m1 removes D, m2 may fork M, a1 may rotate A; the study's rule | **fails** `NoLeakMember` (history box to an ignorant fork) | 3,756 | 15 s |
| `D0_member_anchor` | as D0_member, anchored sealing and merge | no violation (unfinished, stopped at 50 min; partial liveness checks passed) | 529,544+ | 50 min |
| `D0_member_forge` | as D0_member_anchor, D forges a keyset of M | no violation (unfinished, stopped; partial liveness checks passed); before descent skipped invalid keysets: **fails** `NoLeakMember` (an ignorant fork made from the forgery descends from kk through it) | 606,566+ | 37 min |
| `D0_cyc_study` | X {x1, D, Y}, Y {y1, X}; x1 removes D, y1 may rotate Y; the study's cycle rule | **fails** `Settles` (ping-pong) | 2,582 | 37 s |
| `D0_cyc2_study` | X <-> Y, D leaves X and E leaves Y concurrently; the study's rule | **fails** liveness (each left out of the other) | 365 | 7 s |
| `D0_below_study` | W {w1, D} holds X, X <-> Y; w1 removes D; the study's rule | **fails** `NoLeakMember` (a staleness rotation boxes Y) | 26 | 6 s |
| `D0_cyc_reach` | as D0_cyc_study; every rotation leaves out, re-seal by reachability over held boxes | **fails** `NoLeakDirect` (a later ignorant re-seal) | 1,646 | 26 s |
| `D0_cyc` | as D0_cyc_study, Fresh | pass | 2,118 | 24 s |
| `D0_cyc2` | as D0_cyc2_study, Fresh | pass | 2,368 | 36 s |
| `D0_cyc3` | 3-cycle X in Y in Z in X, x1 removes D; Fresh | pass | 144 | 25 s |
| `D0_below` | as D0_below_study, Fresh | pass | 119 | 15 s |
| `D0_below_eager` | as D0_below, y1 may rotate Y | pass | 15,621 | 360 s |
| `D0_cyc_2adm_fresh` | as D0_cyc, a second admin y2 of Y may rotate Y; Fresh | **fails** `NoLeakDirect` (y1, not yet knowing, re-seals Y to X's old keyset after x1 sealed into it on y2's re-seal) | 94,984 | 844 s |
| `D0_cyc_commit` | as D0_cyc; seal only on a box back in the keyset's own commit, rotate to rejoin | **fails** `Settles` (rejoin ping-pong) | 4,384 | 70 s |
| `D0_cyc3_commit` | as D0_cyc3, the commit rule | **fails** `Settles` (rotations chase round the cycle) | 204 | 18 s |

A 3-cycle under Fresh with unprompted rotations of Y and Z ran 34,914 states without a violation before it was stopped (unfinished).

**Rule 4: no key cycles** (`CycleCheck = "nocycle"`, issues/keys-depth0.md, study §4). Actor grants in an agreed order (`Grants`); each node gives key access to the grants it holds greedily in that order (`KH`), seals no keyless grant, and rotates its actor while a current epoch boxes an actor without key access (`Keyless`). `Hidden` grants are missing at a node at first (learned fairly; made later, so initial epochs do not box them); `MaxBlind` bounds the boxes sealed to a holder with no true key access (the ignorance window as one-shot adversary steps). `Taint`: a keyset boxing an actor without key access is stale and never sealed to. Extra properties: `NoLeakKnown`, `NoLeakKnownAll` (a device removed from the actor, or from an actor with no key path to it, reads no content written knowing the removal once every node holds every grant; `All`: and the writer holds every keyset and re-seal). Writes = 2, `Writes = 1` for the hidden ones; MaxE 7. TLC 2.19, 1 worker each, 2-4 runs side by side, load 8-45.

| cfg | instance | result | states | time |
|---|---|---|---|---|
| `D0_nc` | 2-cycle X <-> Y, X holding Y granted first; x1 removes D from X, y1 may rotate Y | pass | 608 | 3 s |
| `D0_nc_rev` | as D0_nc, Y holding X granted first | pass | 814 | 3 s |
| `D0_nc2` | as D0_nc, E leaves Y concurrently | pass | 10,225 | 48 s |
| `D0_nc3` | 3-cycle, Z holding X granted last; x1 removes D | pass | 454 | 10 s |
| `D0_nc_below` | W holds X, X <-> Y; w1 removes D from W; y1 may rotate Y | pass | 11,634 | 141 s |
| `D0_nc_2adm` | as D0_nc_rev, second admin y2 of Y may rotate Y (broke Fresh) | pass | 7,400 | 64 s |
| `D0_nc_hide` | as D0_nc_rev, y1 lacks the earlier grant: seals Y to X's old keyset | **fails** `NoLeakDirect` (expected: the hidden-grant leak) | 39 | 1 s |
| `D0_nc_hide_lim` | as D0_nc_hide, the stated limit, no taint | **fails** `NoLeakKnownAll` (expected: x1, knowing all, writes sealed to Y's keyset that boxes X's old one) | 366 | 5 s |
| `D0_nc_hide_live` | as D0_nc_hide_lim, liveness and member invariants only | pass | 32,896 | 364 s |
| `D0_nc_hide_taint_lean` | as D0_nc_hide_lim with Taint, no unprompted rotation | pass (probes: a blind box of Y to X exists while a knowing write happens) | 7,180 | 54 s |
| `D0_nc_hide_taint` | as D0_nc_hide_taint_lean, y1 may rotate Y | no violation (unfinished, stopped) | 80,949+ | 25 min |
| `D0_nc_2adm_hide_lean` | as D0_nc_2adm without unprompted rotation, y2 lacks the earlier grant; Taint | no violation (unfinished, stopped); safety only (no `PROPERTIES`, 3 workers): no violation, unfinished | 137,813+; 4,882,683+ | 25 min; 15 min |
| `D0_nc3_hide` | as D0_nc3, x1 lacks the grant of X holding Y and seals X to Z; Taint (a probe: `NoLeakDirect` fails, 34 states) | safety only (3 workers): pass; with liveness no violation (unfinished, stopped) | 392,368; 14,426+ | 63 s; 25 min |

Liveness checking dominates: safety-only runs of the same instances go 100-1000 times faster.

Content records now carry the rule-4 premises, so the earlier rows' state counts grow (rechecked: `D0_cyc` passes in 2,737 states, `D0_cyc_study` fails liveness in 3,162).

Without `MaxBlind` (any number of blind seals) `D0_nc_hide_taint_lean` fails liveness at the epoch bound: concurrent re-seals by x1 and the still-ignorant y1 re-form the cycle between fresh keysets, x1 rotates off it, and again, until `MaxE`.

