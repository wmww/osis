# forensic-attack complaints
> Summary: Mishaps while extending the forensic attack.

- Net nodes run on into a crashed device: after a `Fault::Crash` mid-`handle`, further `handle` calls hit the engine's debug cache check (`labels_of(..) cached`) and panic. A test must stop driving the node at the crash, as the process would.
- A per-crash-point `Net` setup costs about 1.5 s; `MemoryBackend::fork` + `MemoryRoot::copy` of the set-up device and `restart` avoids it.
- Typed wrong `claudewait` task IDs twice (copied from memory, not the launch output).
- Review: the crash test took 12.7 s solo (9 attacks × 1.4 s, nearly all in the blob phase: 40K candidates × 17 blobs and their wraps); one thread per blob brought it to 3.7 s. No store test exercised keys found inside opened blobs (disabling that harvest step passed the store suite); added a nested-blob case.
