# random_churn oracle: holders of the same commits read differently after expiries
> Summary: `ephemeral::random_churn_converges_large` fails seeds 138077, 237087 and 237295 and never finishes 140170 and 140188 (all on main too): holders of the same valid ephemeral commits read differently because the non-value writes of expired commits (a reset, a removal, a value-less register winner) stay in the state of nodes that held them at expiry and are gone at nodes that did not, or that rebuilt the aspect since.
> Tags: ephemeral, crdt, tests

Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large --nocapture`. The failure prints each never-demoted holder's reads, the commits held only at one of them (empty in all three), the step log and the lane dump. To see the states, print `EphAspect` (`state`, `own`, `parts`) per node in `lane_dump` (a temporary engine accessor).

Mechanism (traced on 237295): node 2 writes `NgtV=v2` (expiring 20 min) at step 2 and `Replace({k1: r9})` expiring 90 s at step 9. spec/crdt.md §4.7: at expiry a delta's value-carrying writes go value-less, its non-value writes (the map reset) stay. Ephemeral bodies are dropped at expiry, so the reset stays only in the state of nodes that held the commit then. Node 0 did (it promoted the commit after node 2's demotion and promotion, before it expired) and reads no `v2`; node 3 held it invalid while node 2 was demoted, was offline when it expired, and reads `v2`. Both hold the same 22 commits. The same split appears inside one node: `rebuild_aspect` (any validity flip, `rejudge_ephemeral`) joins own writes and held parts only, so it drops the remnants of expired parts the node did keep; and an author's own expired writes are stripped from `own` differently from a holder's copy (237087: node 0's own expired flag write is gone at node 0, its value-less copy wins the register at nodes 2 and 3). 138077: an entry reset (`ed1e5ad2:4`) of node 3's earlier session is in nodes 0 and 3's state, not in 1 and 2's.

So the state is not a function of the held valid commits, which the oracle (and "state outlives its author") assumes. Directions:
- Ephemeral expiry removes a part whole (un-merge, spec/crdt.md §4.6): state = own live writes joined with the live valid held parts, at every node and for the author's own writes. Departs from §4.7 for ephemeral data (an expiring removal stops removing at T); needs the spec and the author's `own` stripping changed. Simplest and convergent.
- Keep remnants: impossible for a node that never held the body (ephemeral bodies are gone everywhere once expired).

Fixed earlier on this oracle: 203 (eph-restart-seeds); 154, 169, 118077, 119026, 237008, 237140, 237171 (eph-churn-demote: a demoted author's commits, fetched back to wait apart, were marked present at a host that had restarted since and carried a stamp under a write key from before the rotation, so nobody put them back; spec/sync.md §6).

140170 and 140188 (eph-churn-demote run 140000..140300) never finish, on main too: the seed timeout stops the run (use `OSIS_SEED_TIMEOUT_SECS=60`). Not traced; the lane is not what loops (`OSIS_EPH_TRACE=all` prints about 1500 events in 15 s, none repeating much).

Each seed found later goes here with its class; the oracle is a periodic check until this list is empty.
