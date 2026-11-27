# sheave-c20-memory
> Summary: No tool shows what a followed key's reads are; finding the fan-in took a hand-written dump.

memprof says how many bytes an `Effects`'s record and index hold, not which containers the reads are in. A temporary dump (per `Effects`, reads by container name and distinct keys) found it at once: per commit about 45 reads over a few dozen distinct keys, the per-thing derivations copied in. Backtraces from `Dep::new` were no use first: the dev profile's frames under the cutoff closures give no function names. What would have prevented it: a by-hand `Effects::reads_by_container` (or a `costs` count of reads kept by container at settle) beside `Effects::reads_held`.
