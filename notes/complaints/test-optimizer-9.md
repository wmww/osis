# test-optimizer-9
- `tools/pertest.py run` MATCH takes `<package> <target>`; the engine lib is `osis-engine osis_engine`, not `osis-engine lib`: a wrong MATCH silently drops the binary (no "matched nothing" line).
- A planted fault that makes every duplicate ingest re-apply slowed the engine lib past 7 minutes (tests over 60 s each): plant a fault that fails fast (an error) when measuring a harness change.
- Rebuilding while a plant loop runs replaces the binary under it (same deps path): keep plant sets fixed per run or copy the binary first.
- The cut twins seeded `Rng(seed * K + c)`: the gate draws `_large` starts near 1e12, so every gate seed overflowed (debug panic) while the 40-seed plant runs at 1-40 passed; a seeded rng built from a seed wraps.
