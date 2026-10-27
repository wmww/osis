# Sync convergence (TLA+)
> Summary: TLC model of one label's blobs at one blind server (spec/sync.md §5–§7, spec/commits.md §5): upload, download, deposit, token delete with carriers (blob-ID tiebreak), timed delete with a snapshot first, expiry, compaction, due snapshots (before a deletion, a live drop or a timed delete), purge, tombstones, offline nodes, a dropping/replaying/reordering server. Written from spec/ alone.

Files: `SyncConvergence.tla` (the model), `MC.tla` (scenario constants), one `.cfg` per instance, `ASSUMPTIONS.md`, `AMBIGUITIES.md` (the findings).

## Run
`../run.sh small` (CI-sized instances of both models) or `../run.sh all`; it fetches TLC into `~/.cache/tla/` if missing. By hand, from this directory (Java 11+):
```
java -XX:+UseParallelGC -cp ~/.cache/tla/tla2tools.jar tlc2.TLC -workers 1 \
  -metadir /tmp/tlc-states -config deposit.cfg MC
```
Keep state directories out of the repo (`-metadir`).

## Properties
Invariants: `NoLiveLoss` (sync §7: a body with live writes leaves the label only while another entry carries them), `LiveKept` (sync §7 "Live state is never lost": every live write is in a node's state or carried at the server; true by construction, nothing evicts state). Temporal, under weak fairness of honest steps: `Converge` (sync §6: every must-hold body ends up at the server), `Clean` (sync §6/§7: no must-not-hold body or duplicate persists there), `Quiesce` (no endless upload/delete alternation: the server's entries settle), `Promoted` (sync §5: a deposited commit the label must hold gets stamped), `PurgeReachesAll` (commits §5: every node ends up holding no purged body), `Serves` (sync §7 "a member serves current state from the bodies and snapshots it holds": eventually every live write a node holds in state is carried by a body or snapshot it holds).

## Instances and results
TLC 2.19, 1 worker, on a shared 4-core machine at load ~10 (wall clock, another TLC run beside). Every instance passes. Hardening rerun: "the label lacks" follows sync §6 (a blob of the commit holding every delta no snapshot there covers holds the body) and snapshots respect the frontier rule (commits §5). S17 rerun (2 workers, box shared with a cargo build and a sim sweep): a must-not-hold blob holds nothing, so the purger uploads its rewrite beside the purged superset again and a writer that has not applied the purge deletes it until it does; the purge instances grew from 8,698 to 88,928 states.

| cfg | scenario | result | states | time |
|---|---|---|---|---|
| `deposit.cfg` | writer + reader; deposit and promotion, expiry, relay, 1 lost entry, 1 stale replay, 1 offline | all pass | 3,148 | 5 s |
| `mostabs.cfg` | writer + reader; live write under absolute keep-at-most, snapshot before the drop (S11), checks `Serves` too | all pass | 178 | 4 s |
| `timed.cfg` | 2 writers; supersede under keep-at-most 1 after replaced (timed delete), optional snapshot and compaction; time 0..2 | all pass | 44,773 | 20 min |
| `timed_live.cfg` | as timed.cfg with a two-delta body that keeps a live write past the bound: snapshot before the timed delete (S13); one encryption per body | all pass | 7,353 | 174 s |
| `purge.cfg` | 2 writers; purge of a reset write in a 2-delta commit (rewrite, strict-subset rule), re-snapshot; no time | all pass | 88,928 | 540 s |
| `purge_reach.cfg` | as purge.cfg, checks `PurgeReachesAll` | pass | 88,928 | 515 s |

`run.sh small` runs `deposit.cfg` and `mostabs.cfg`.

## Not covered
Several labels or servers, projections, certificate copies, retagging, parked bodies and unfetched pages, clock skew, range reconciliation details, token levels (every writer holds every token), `nobody`/`admin`/`author` purge rights, nodes offline longer than `MEMBERSHIP_KEEP` (time never reaches a purge commit's bound), concurrent deletes from stale views and covered-equal snapshots (S12; the tiebreak is modeled, the race is not), at most 0 after replaced, snapshots covering snapshots, clock-offset sampling, connections and request timeouts, signals (sync §9).
