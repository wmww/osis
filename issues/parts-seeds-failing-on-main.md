# Parts differential seeds failing on main
> Summary: `parts::parts_differential_large_spec_commits_4` seeds 934068, 936047 (variant 4) and 936059 (variant 2, `t:map.0`) fail on main ff46dfee. 934068 (variant 4, fixed sync, as delivered and blobs come) misses body lines of commit 964a774f… (`t:reg.0` "valid dropped", `t:count.0` "invalid missing") and a thing line that the reference holds; not classified.
> Tags: tests, engine

Replay: `OSIS_PARTS_START=934068 OSIS_PARTS_SEEDS=1 cargo test --workspace --test it parts::parts_differential_large_spec_commits_4 -- --ignored --exact`. Found by the pending-drops review (ranges 934000 and 936000, 150 seeds each: these three only, the same on main and the branch).
