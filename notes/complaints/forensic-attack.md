# forensic-attack complaints
> Summary: Mishaps while extending the forensic attack.

- Net nodes run on into a crashed device: after a `Fault::Crash` mid-`handle`, further `handle` calls hit the engine's debug cache check (`labels_of(..) cached`) and panic. A test must stop driving the node at the crash, as the process would.
- A per-crash-point `Net` setup costs about 1.5 s; `MemoryBackend::fork` + `MemoryRoot::copy` of the set-up device and `restart` avoids it.
- Typed wrong `claudewait` task IDs twice (copied from memory, not the launch output).
