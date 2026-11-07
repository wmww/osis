# judgment_vectors_can_fail: one case passes with a shorter order
> Summary: osis-node tier-2 `judgment::judgment_vectors_can_fail` fails: case "edge with an invite above its role, by an invite holder, as made" still passes its replay with the last order step dropped ("a shorter order passes: 52"), so the vector's last step is not load-bearing. Still fails on main. Fix the vector (or the check's exception list) so dropping the last step changes the verdict.
> Priority: normal
> Tags: tests, permissions

Repro: `cargo test -p osis-node --test it -- --ignored --exact judgment::judgment_vectors_can_fail` (3 s). `judgment::judgment_vectors_write` also fails in an `--include-ignored` run, by design (it needs `OSIS_WRITE_VECTORS=1`); the periodic command should skip it.
