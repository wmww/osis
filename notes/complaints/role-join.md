# role-join
- The repro's history shape (holders `i % 50`, toggled every 50) had no removal at n=30 and 150 at 300, so "commits walked 1 -> 151" compared different mixes, not scaling; the 151 were one shadow walk per removal, flat. A counted n/10n test needs the same mix of ops at both sizes.
- Finding who walks or writes needed throwaway backtrace and store-key tracing; nothing counts work by caller or store bytes by table/aspect. `MemoryBackend::io` sees only encrypted unit rows (about 5x the logical bytes).
- Store bytes in an n/10n check can't be read below `PAGE_TARGET`: a state under 64 KB is written whole per write, so any aspect with tombstones (here `roles.0`) looks quadratic until paged, and paged sizes are too slow for a default test.
