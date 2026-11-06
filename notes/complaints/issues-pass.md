# issues-pass
- Seed issues name seeds whose generated histories drift with the generator: a seed replay passing proves little (seed 73310002 passes while its shrunk history still fails). Issues should carry the shrunk history and a `check(..)` line, as most do; pinning one takes a throwaway test.
- Code and TLA comments cite issues by path (core/test/tla/rotation/{Depth0.tla,README.md}, core/test/tla/run.sh), so deleting a solved issue under a no-code-change rule leaves dangling links nothing checks.
