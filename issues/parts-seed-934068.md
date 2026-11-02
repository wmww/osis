# Parts differential seed 934068 fails on main
> Summary: `parts::parts_differential_large_spec_commits_4` seed 934068 (variant 4, fixed sync, as delivered and blobs come) misses body lines of commit 964a774f… (`t:reg.0` "valid dropped", `t:count.0` "invalid missing") and a thing line that the reference holds. Fails on main ff46dfee too; not classified.
> Tags: tests, engine

Replay: `OSIS_PARTS_START=934068 OSIS_PARTS_SEEDS=1 cargo test --workspace --test it parts::parts_differential_large_spec_commits_4 -- --ignored --exact`. Found by the pending-drops review (range 934000..934150, the only failing seed).
