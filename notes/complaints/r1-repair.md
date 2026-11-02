# r1-repair
- `cargo test --workspace` stops at the first failing test binary: a broken codegen test hid every later binary's result for a 10-minute run. Use `--no-fail-fast` for a full picture.
- Two arguments after `--test it` (`cargo test --test it a b`) is a cargo usage error that a `| grep` hides completely: the run looked like "no output". Put filters after `--`.
- An offline `Net` node is not ticked by `Net::advance`: a test of timers at an offline node must call `engine.tick()` itself.
- Tier 1 at load 40-45 took 6-11 min wall.
- Review: an ad-hoc `OSIS_*` env switch in a test panics the run (`core/base/testenv-known.txt` lists the known ones); a probe switch needs another prefix. Useful guard, surprising the first time.
- Review: a one-line text change in a `judgment::` scenario's `source` fails `judgment_vectors_spec_permissions_5_2` until the vectors are regenerated (`OSIS_WRITE_VECTORS=1 ... judgment_vectors_write`); the assertion message says so, but only after a 15 s run.
