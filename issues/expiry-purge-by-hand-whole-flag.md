# A reload marks an expired-and-purged part's leftover whole where the live node does not
> Summary: shred.rs `past_expiry_and_purge_alike_in_every_order_by_hand_spec_commits_5` (by hand, every order) fails on main: in 16 of its cases the store loaded afresh holds the stripped `t:reg.0` part's leftover as a whole replace (`whole: {1}`) where the live index does not (`Engine::check_index`, "rebuilt from the commit records").
> Priority: normal
> Tags: engine, tests

- Reproduce: `cargo test -p osis-engine --test it -- --ignored --exact shred::past_expiry_and_purge_alike_in_every_order_by_hand_spec_commits_5` (about 400 s on every core: run under `tools/heavy`). The default `past_expiry_and_purge_alike_spec_commits_5` passes.
- Live: `dropped: {0, 2}, stripped: {1}, whole: {}`; reloaded: the same with `whole: {1}` (`Hold::Leftover::whole`, which a load reads from the leftover by `snapshot::whole_replace`). One of the two paths sets it wrongly for a leftover left once both expiry and purge took the part.
- Which cases fail is not recorded yet: print the failing case's shape and order (the test's `outcomes` map) first.
