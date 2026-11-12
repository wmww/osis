# ephemeral_capped: a refreshed cursor never read
> Summary: sim `ephemeral_capped` setup 963785799942 seed 963785799947 fails at step 300 (on main alike): "node 2 does not read node 0's refreshed cursor c67 (refresh 2)". Not studied.
> Priority: normal
> Tags: ephemeral, sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 963785799947 --setup 963785799942 --only ephemeral_capped`; `OSIS_SIM_TRACE=1` for the messages.
- Start at: whether node 2's or the capped host's cap refused the refresh's entry and nothing fetched it again (spec/sync.md §9 Caps: refetch once the label's held bytes drop below the refusal's).
