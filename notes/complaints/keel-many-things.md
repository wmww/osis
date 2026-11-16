# keel-many-things
- `tools/cpuprof --report` symbolizes against the binary file as it is now: after a rebuild the report of an old sample file is garbage (wrong test names at 100%). Copy the binary aside before profiling.
- `ls -t target/debug/deps/it-*` picks whichever crate's `it` built last (osis-sync's, not osis's): take the path from `cargo test -p <crate> --test it --no-run`.
- The making test excluded `stream: bytes` as "fits in one page"; that hid an O(state) decode per cover judgment. Counted kinds that are flat can still hide growing work inside one count (a settle of a whole-set value counts 1).
