# pull-cursor-2
- Comparing a count with main's module (`git checkout origin/main -- core/sync/src/streams ...`) needs the test files that call new APIs checked out too (streams.rs here), or the probe silently prints nothing: the grep hid the compile error. Check the probe's output is non-empty.
- A trace filter on a blob ID (`OSIS_SYNC_TRACE=2:B612c17`) hides the frames that explain an ordering (the message in hand ahead of the one showing the blob); a second trace on `DBG,PullReply,FetchReply` with temporary notes was needed.
- `first::` costs about 10 s per process for two fixture sizes; a 10n size (to see a growth shape past n = 1) is by hand only (`probe_first`), so the default test bounds 5n against n, where n = 1 is itself a special case.
