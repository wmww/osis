# random_churn_converges_large: seed 884 never quiesces
> Summary: seed 434801186884 of `ephemeral::random_churn_converges_large` panics "no quiescence after 2000 rounds (24317 messages): a loop" in a `settle`: some message exchange repeats forever. Fails on main (20a9fa56b) as on branch trigger-rewake (found by its gate). Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `OSIS_EPH_START=434801186884 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (20 s).
- Next: trace the last rounds' messages (`net/mod.rs` `settle`) to find which pair loops and on what.
