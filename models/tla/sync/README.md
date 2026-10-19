# Sync convergence (TLA+)
> Summary: TLC model of one label's blobs at one blind server (spec/sync.md §5–§7, spec/commits.md §5): upload, download, deposit, token delete, timed delete, expiry, compaction, purge, tombstones, offline nodes, a dropping/replaying/reordering server. Written from spec/ alone.

Files: `SyncConvergence.tla` (the model), `MC.tla` (scenario constants), one `.cfg` per instance, `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
TLC is not vendored. Download it once (not into the repo):
```
mkdir -p ~/.cache/tla
curl -sSL -o ~/.cache/tla/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```
Then, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config timed.cfg MC
```
Swap `timed.cfg` for any instance below. Keep state directories out of the repo (`-metadir`).

## Properties
Invariants: `NoLiveLoss` (sync §7: a body with live writes leaves the label only after a covering snapshot is there), `MemberCanServe` (sync §7: a member can always serve current state). Temporal, under weak fairness of honest steps: `Converge` (sync §6: every must-hold body ends up at the server), `Clean` (sync §6/§7: no must-not-hold body or duplicate persists there), `Quiesce` (no endless upload/delete alternation: the server's entries settle), `Promoted` (sync §5: a deposited commit the label must hold gets stamped), `PurgeReachesAll` (commits §5: every node ends up holding no purged body).

## Instances and results
TLC 2.19, 1 worker, on a shared loaded 4-core machine.

| cfg | scenario | result | states | time |
|---|---|---|---|---|
| `timed.cfg` | 2 writers; supersede under keep-at-most 1 after replaced (timed delete), snapshot, compaction; time 0..2 | all pass | 35,037 | 5 min |
| `purge.cfg` | 2 writers; purge of a reset write in a 2-delta commit (rewrite, strict-subset rule), re-snapshot; no time | all pass | 388,466 | 17 min |
| `purge_reach.cfg` | as purge.cfg, checks `PurgeReachesAll` | **fails** (S1), 15-state trace | 3,684 (partial) | 4 s |
| `mostabs.cfg` | writer + reader; live write under absolute keep-at-most | **fails** `MemberCanServe` (S2); without it `Clean` fails | 7 / 314 | 2 s |
| `deposit.cfg` | writer + reader; deposit and promotion, expiry, relay, 1 lost entry, 1 stale replay, 1 offline | all pass | 3,148 | 6 s |

The smallest clean instance for CI is `deposit.cfg`.

## Not covered
Several labels or servers, projections, certificate copies, retagging, parked bodies and unfetched pages, clock skew, range reconciliation details, token levels (every writer holds every token), `nobody`/`admin`/`author` purge rights.
