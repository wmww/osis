# member_churn: a label never opens at a host
> Summary: sim `member_churn` setup 313462591648 seed 313462591654 fails at step 153 (on main alike): node 2's connection to host 0 keeps group cqIs..'s label Testing (head None, synced false) at quiescence. Not studied.
> Priority: normal
> Tags: sync, sim, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 313462591654 --setup 313462591648 --only member_churn`; `OSIS_SIM_TRACE=1` for the messages.
- Start at: why node 2 never registers or opens that label there (a step refused for now and not registered again, or a head it never read); two `delete refused: code 1` diagnostics at step 29.
- With merges made by the roster merger (spec/crypto.md §4, Merger) the seed passes: its run makes far fewer role commits, so it no longer reaches this state. Whether the label stays unopened in another run is unknown; a reproducer is needed before a fix.
