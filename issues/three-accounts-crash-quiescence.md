# three_accounts_two_hosts: not quiescent after a host crash (seed 971000000009)
> Summary: sim `three_accounts_two_hosts` setup 971000000000 seed 971000000009 fails on main alike: "not quiescent after 60 rounds", one more round still adding many content and snapshot entries at s1 (host 1 crashed at its write 6 earlier in the run) and deleting two commits' larger blobs (`[1, 2]` reg.0 + created.0) beside rewrites of their parts. Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 971000000009 --setup 971000000000 --only three_accounts_two_hosts`; `OSIS_SIM_TRACE=1` for the loop.
- Start at: whether this is slow refill after the crash (60 rounds too few: the added set shrinking round over round) or a loop (the same entries placed again); the paired delete of a `[1, 2]` blob beside a placement of part `[2]` suggests a rewrite of a commit one node holds part of.
