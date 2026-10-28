# test-threads complaints
> Summary: mishaps met while parallelizing the walks seed runs and pooling the osis-perm shards.

- Timing comparisons on a shared box are noisy: the same pooled perm run took 172 s through cargo and 142 s run directly a minute later (other agents' load moved 15-85). Compare runs back to back and with an env knob (`OSIS_PERM_THREADS=1000` reproduces the unbounded case) rather than across builds.
- `walks::open_equals_rebuild_random_histories` as a name filter also matches `_moves` and `_carried_imports`; replay commands need `-- --exact`.
