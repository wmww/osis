# roster-measure
- The release `osis-node` test build took 3-10 min per small test edit at load 15-35; each 10^4 measurement 4-25 min, the roster-snapshot write and ingest most of it.
- Started three 10^4 runs as detached shell jobs instead of `run_in_background`, so `claudewait` could not track them; read their logs after the tracked run ended.
- `/proc/self/stat` parse: `tpgid` is -1, a u64 parse drops it and shifts the fields (first run read stime as CPU time).
