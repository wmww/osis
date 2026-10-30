# Replayed old ephemeral commits fill every holder's cap
> Summary: absorption is checked only against covers held now and plain ephemeral commits have no age bound, so anyone holding old stamped entries (a reader, or a blind server that kept them) can re-inject an author's commits from two or more covers back: every holder keeps them, spreads them to the other servers and counts them toward its per-label cap. Once the cap is full the label stops converging at that node until it restarts. High.
> Tags: security, engine, node, ephemeral

Scenario. Author A writes, covers (C1 absorbs A1..Ak), covers again (C2 absorbs C1). Holders keep only C2. An attacker that kept A1..Ak (and any commit since that is not directly absorbed by a held cover) uploads them again:
- a reader: stamps stay valid while the head's write key does not change; the server refuses them only while a tombstone stands (`EPH_TOMBSTONE_MS` = 1 h, in memory only, so it is gone after a server restart or an eviction at the total cap);
- a blind server: it just serves blobs it kept to its clients. No stamp check runs at nodes, and blobs from older epochs still open with the history secrets, so it can replay any old ephemeral commit of the group.

At each holder, `ingest_ephemeral` (core/engine/src/ephemeral/remote.rs:820-829) drops a commit only if `eph_covered` finds a *held* commit that lists it as absorbed (:779). A1 is listed only by C1, which is gone, so A1 is verified, held, kept in the lane (core/node/src/sync/ephemeral.rs:969, counted in `Lane::bytes`) and spread to the other servers (:971). Commits of authors that have left are never covered again, so they stay until restart. An author that is still online covers them again at its next cover. That costs the author work, but the attacker can repeat it.

Effects:
- Node cap: once `Lane::bytes` passes `SyncConfig::ephemeral_bytes` (ephemeral.rs:920), every later ephemeral commit of the label is refused there, honest ones included. What was refused is not fetched again until a restart (`refused`), so holders stay diverged even after bytes drop.
- Server caps: holders upload the replayed commits to every server, so honest uploads there get code 12.
- Delete churn: replays of commits that *are* directly covered make every writer holder send a delete (`Dropped { absorbed: true }`, ephemeral.rs:953). These draw on the label's delete rate, so honest covers that carry replacements get code 4 (core/server/src/store.rs:1360-1366).
- Commits of removed members replayed by a blind server are held as invalid parts and still counted.

Fix direction: make absorption effectively transitive at holders. When a cover drops X, it inherits X's absorbed IDs as an in-memory implied set, or each (author, actor, class) keeps a floor of absorbed IDs. Bound this and look at it with notes/arbitrary-values.md. Do not hold, or count, parts that are invalid on arrival. Let a label whose cap was hit reconcile once bytes drop, instead of staying refused until restart. Presence variant: issues/eph-presence-replay-pin.md.
