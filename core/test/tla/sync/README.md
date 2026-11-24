# Sync convergence (TLA+)
> Summary: TLC model of one sync ID's blobs at one store (spec/sync-ids.md §6, spec/commits.md §5, history modes): logging, pulling, deposit, deletes by delete key with carriers (per live write: a covering snapshot or another blob of the commit, blob-ID tiebreak), expiry, compaction, keep-at-least (until T and/or D after replaced, a limit on the compactor), purge on replace (a replaced body's cover owed by every writer holding it, the body gone once covered), due snapshots (before a deletion, an owed cover, a purge), purge, tombstones, offline nodes, a dropping/replaying/reordering store. Written from spec/ alone.

Files: `SyncConvergence.tla` (the model), `MC.tla` (scenario constants), one `.cfg` per instance, `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
`../run.sh sync` (about 40 s at one worker; the other cfgs by name, `../run.sh sync <cfg>`); it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir ../../../../target/tlc-states -config deposit.cfg MC
```
Keep state directories out of the repo (`-metadir`).

## Properties
Invariants: `NoLiveLoss` (sync §7: a body with live writes leaves the sync ID only while another entry carries them), `LiveKept` (sync §7 "Live state is never lost": every live write is in a node's state or carried at the store; true by construction, nothing evicts state), `StateCarried` (crdt §4.6, commits §5: a node's state is the join of the bodies it holds: every live write in its state is carried by a body or snapshot it holds, at all times), `KeptUntil` (commits §5: before its keep-at-least, T and/or D after its kill, a body leaves a node or the store only by purge or expiry). Temporal, under weak fairness of honest steps: `Converge` (sync §6: every must-hold body ends up at the store), `Clean` (sync §6/§7: no must-not-hold body, covered body under purge on replace or duplicate persists there), `Quiesce` (no endless log/delete alternation: the store's entries settle), `Promoted` (sync §5: a deposited commit the sync ID must hold gets stamped), `PurgeReachesAll` (commits §5: every node ends up holding no purged body), `PorCovered` (commits §5 purge on replace: no writer ends up holding such a body replaced and uncovered).

## Instances and results
TLC 2.19, 2 workers, on a shared 4-core machine (wall clock). Every instance passes.

| cfg | scenario | result | states | time |
|---|---|---|---|---|
| `deposit.cfg` | writer + reader; deposit and promotion, expiry, a reader logging a stamped entry, 1 lost entry, 1 stale replay, 1 offline | all pass | 3,148 | 9 s |
| `kept.cfg` | writer + reader; a write kept until T = 1 and a snapshot covering it: never compacted before T | all pass | 101 | 3 s |
| `kept_after.cfg` | writer + reader; a write kept D = 1 after replaced, its kill and a snapshot: the writer compacts only past the kill plus D | all pass | 3,270 | 9 s |
| `por.cfg` | 2 writers; a write under purge on replace replaced, each writer holding it owes a cover (s1, s2); the body goes as covered everywhere; time 0..1 | all pass | 228,943 | 598 s |
| `por_live.cfg` | as por.cfg with a two-delta body keeping a live write, carried by the covers (under purge on replace themselves); one encryption per body | all pass | 12,931 | 24 s |
| `purge.cfg` | 2 writers; purge of a reset write in a 2-delta commit (rewrite, strict-subset rule), re-snapshot; no time | all pass | 122,810 | 237 s |
| `purge_reach.cfg` | as purge.cfg, checks `PurgeReachesAll` | pass | 122,810 | 281 s |

`run.sh sync` runs `deposit.cfg`, `kept.cfg`, `kept_after.cfg` and `por_live.cfg`.

## Not covered
Several sync IDs or stores, projections, certificate copies, retagging, parked bodies and unfetched pages, clock skew, range reconciliation details, delete-key levels (every writer holds every delete key), `nobody`/`admin`/`author` purge rights, nodes offline longer than `ROLE_KEEP` (time never reaches a purge commit's bound), concurrent deletes from stale views and covered-equal snapshots (S12; the tiebreak is modeled, the race is not), snapshots covering snapshots, a cover turning invalid (validity is not modeled), clock-offset sampling, connections and request timeouts, signals (sync §9).
