# random_churn oracle: three seeds diverge with superseding off too
> Summary: `ephemeral::random_churn_converges_large` fails seeds 154, 169 and 203 of 0..300 whether or not superseded expiring writes are dropped: 154 and 169 after demotions and re-promotions (holders differ in holding a demoted-then-promoted author's commits and read its key differently), 203 with no demotion of the differing node (a twice-restarted author reads its post-restart writes, the others hold the same commits and read older values).
> Tags: ephemeral, node-sync, tests

Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large --nocapture`. The failure prints each never-demoted holder's reads, the commits held only at one of them and the step log.

- 154, 169: probably the family of issues/eph-cover-invalidated-loses-absorbed.md (validity judged at the stamp, a drop final across a demotion). The oracle already skips nodes once demoted, whose view of their own writes differs from everyone's (an author always reads its own writes).
- 118077 (fails with superseding off too): same class; node 0 holds five of demoted-then-promoted node 2's commits and reads its key, node 3 (restarted) holds none.
- 203: same held set at every holder, yet node 3's step-54 writes (flag `f54`, `k1=v54`) read only at node 3. Not yet understood.

Each seed found later goes here with its class; the oracle is a periodic check until this list is empty.
