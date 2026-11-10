# Two osis-cli localhost tests fail on main
> Summary: `localhost::own_serving_node_localhost` (Alice's `sync`: her own serving peer "does not admit group ... (yet)") and `localhost::two_accounts_three_nodes_one_peer_localhost` (`get` of a thing synced through the peer: absent) fail every run at 5323f817e; not root-caused.
> Priority: normal
> Tags: cli, host, node-sync, tests

By hand only (`cargo test -p osis-cli --test it -- --ignored localhost::`, notes/testing.md By hand, Networking), so the gate never runs them. Both route a group through a saved peer serving it under `host^.0` `own`. The other three localhost tests pass. Find the commit that broke them (bisect over the by-hand command) and fix it.
