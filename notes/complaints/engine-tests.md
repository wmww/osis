# engine-tests
- core/base/testenv-known.txt is in append order, not sorted: a `sort` (or python `sorted`) to place two new names rewrote 40 lines. Append new names at the end.
- Many engine default tests still loop a random generator over fixed seeds (`for seed in 0..N` with an `Rng(seed...)`): seed runners by notes/testing.md that never became properties. Grep `for seed in` under core/engine before writing a new one.
- `tools/pertest.py run` per test counts each test's cached fixture whole (most of a 1.3 G validity test is `net(3)`); judge a merge by `tools/icount BIN -q <module>::`, which is what the gate pays.
