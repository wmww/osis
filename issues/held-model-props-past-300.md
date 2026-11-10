# held-model's convergence properties fail past their default 300 seeds
> Summary: With `SEEDS` raised to 2400 in core/test/held-model/tests/it/props.rs, `arrival_orders_read_alike_after_repair_spec_commits_5` fails at seed 138 and `late_commit_converges_after_repair_spec_commits_5` at seed 2336 (a late `Role` commit: one node reads a register the other does not), on main (b0580b907) as on `expiry-2`. The README says 2400 seeds pass.
> Priority: normal
> Tags: tests, held-model

Replay: set `SEEDS` to 2400 (or start the loop at the seed) and run `cargo test -p held-model --test it props::`. Registers and role edges only in 2336's diff, so likely unrelated to expiry.

One cause, fixed in `settle`: a part thrown out as unknown (`DropWhy::Unknown`) from a commit that stays held, waiting on a parked part, was never fetched again once its thing was known (the refetch looked at applied commits only). Whether 138 and 2336 had other causes is not checked (the generator's draws changed since).
