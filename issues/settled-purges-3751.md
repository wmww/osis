# A settled history's node reads absent before its exchange where the keep-everything node reads a value
> Summary: A settled history with purges (the order harness's seed 3751) fails the `settled` pre-exchange check: in one random order a node reads `None` on a map or register aspect (`t:docs.0` as made, `t:gone.0` shrunk) where the node keeping every body reads a value. Not root-caused.
> Priority: normal
> Tags: engine, retention, tests

Replay: `cargo test -p osis-node --test it -- --ignored --exact order::repro_settled_purges_3751` (the history as the order harness made it, in its orders; 5 s). Order #8 of 165 packs, `now, settled`, `t:docs.0` want `{k1: v6}`, got `None`. Shrunk to 36 steps / 144 packs: `t:gone.0` want `"v2"`, got `None`.

The node agrees after its exchange (every order passes with the `settled` check off): a body missing until a copy arrives, not a lasting split like issues/purge-author-order-452234901986.md. In order #8 the node never reads `t:docs.0` as anything: one content write (#13, peer 1, `{k1: v6}`) and peer 1's snapshots of it all leave it absent until the refetch. Open: which rule drops them before the exchange, and whether the `settled` check should spare it (a Deterministic limit, computed from the history) or the drop is one no rule allows. The history has purges, compactions, a demotion of peer 1 and a leave.
