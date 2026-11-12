# member_churn: a label never opens at a host
> Summary: sim `member_churn` setup 313462591648 seed 313462591654 fails at step 153 (on main alike): node 2's connection to host 0 keeps group cqIs..'s label Testing (head None, synced false) at quiescence. Not studied.
> Priority: normal
> Tags: sync, sim, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 313462591654 --setup 313462591648 --only member_churn`; `OSIS_SIM_TRACE=1` for the messages. Same setup, seed 313462591652 storms on role commits (issues/rotation-storm-after-grant-end.md).
- Start at: why node 2 never registers or opens that label there (a step refused for now and not registered again, or a head it never read); two `delete refused: code 1` diagnostics at step 29.
