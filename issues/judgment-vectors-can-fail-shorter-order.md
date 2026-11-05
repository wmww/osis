# judgment_vectors_can_fail: one case passes with a shorter order
> Summary: osis-node tier-2 `judgment::judgment_vectors_can_fail` fails: case "edge with an invite above its role, by an invite holder, as made" still passes its replay with the last order step dropped ("a shorter order passes: 72"), so the vector's last step is not load-bearing. Fails on 02be71d2e too. Fix the vector (or the check's exception list) so dropping the last step changes the verdict.
> Tags: tests, permissions

Repro: `cargo test -p osis-node --test it -- --ignored --exact judgment::judgment_vectors_can_fail` (3 s). Found in periodic run 15 (whole tier-2 set). `judgment::judgment_vectors_write` also fails in an `--include-ignored` run, by design (it needs `OSIS_WRITE_VECTORS=1`); the periodic command should skip it.
