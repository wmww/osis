# Sync convergence (TLA+)
> Summary: TLC model of one label's blobs at one host (spec/sync.md §5–§7, spec/commits.md §5, history modes): upload, download, deposit, token delete with carriers (per live write: a covering snapshot or another blob of the commit, blob-ID tiebreak), expiry, compaction, keep-until, `none` (a replaced body's cover owed by every writer holding it, the body gone once covered), due snapshots (before a deletion, an owed cover, a purge), purge, tombstones, offline nodes, a dropping/replaying/reordering host. Written from spec/ alone.

Files: `SyncConvergence.tla` (the model), `MC.tla` (scenario constants), one `.cfg` per instance, `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
`../run.sh small` (CI-sized instances of both models) or `../run.sh all`; it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config deposit.cfg MC
```
Keep state directories out of the repo (`-metadir`).

## Properties
Invariants: `NoLiveLoss` (sync §7: a body with live writes leaves the label only while another entry carries them), `LiveKept` (sync §7 "Live state is never lost": every live write is in a node's state or carried at the host; true by construction, nothing evicts state), `StateCarried` (crdt §4.6, commits §5: a node's state is the join of the bodies it holds: every live write in its state is carried by a body or snapshot it holds, at all times), `KeptUntil` (commits §5: before its keep-until T a body leaves a node or the host only by purge or expiry). Temporal, under weak fairness of honest steps: `Converge` (sync §6: every must-hold body ends up at the host), `Clean` (sync §6/§7: no must-not-hold body, covered `none` body or duplicate persists there), `Quiesce` (no endless upload/delete alternation: the host's entries settle), `Promoted` (sync §5: a deposited commit the label must hold gets stamped), `PurgeReachesAll` (commits §5: every node ends up holding no purged body), `NoneCovered` (commits §5 history `none`: no writer ends up holding a replaced `none` body uncovered).

## Instances and results
TLC 2.19, 2 workers, on a shared 4-core machine (wall clock). Every instance passes.

| cfg | scenario | result | states | time |
|---|---|---|---|---|
| `deposit.cfg` | writer + reader; deposit and promotion, expiry, relay, 1 lost entry, 1 stale replay, 1 offline | all pass | 3,148 | 9 s |
| `kept.cfg` | writer + reader; a write kept until T = 1 and a snapshot covering it: never compacted before T | all pass | 101 | 3 s |
| `none.cfg` | 2 writers; `none` write replaced, each writer holding it owes a cover (s1, s2); the body goes as covered everywhere; time 0..1 | all pass | 228,943 | 598 s |
| `none_live.cfg` | as none.cfg with a two-delta body keeping a live write, carried by the covers (`none` themselves); one encryption per body | all pass | 12,931 | 24 s |
| `purge.cfg` | 2 writers; purge of a reset write in a 2-delta commit (rewrite, strict-subset rule), re-snapshot; no time | all pass | 122,810 | 237 s |
| `purge_reach.cfg` | as purge.cfg, checks `PurgeReachesAll` | pass | 122,810 | 281 s |

`run.sh small` runs `deposit.cfg`, `kept.cfg` and `none_live.cfg`.

## Not covered
Several labels or hosts, projections, certificate copies, retagging, parked bodies and unfetched pages, clock skew, range reconciliation details, token levels (every writer holds every token), `nobody`/`admin`/`author` purge rights, nodes offline longer than `ROLE_KEEP` (time never reaches a purge commit's bound), concurrent deletes from stale views and covered-equal snapshots (S12; the tiebreak is modeled, the race is not), snapshots covering snapshots, a cover turning invalid (validity is not modeled), clock-offset sampling, connections and request timeouts, signals (sync §9).
