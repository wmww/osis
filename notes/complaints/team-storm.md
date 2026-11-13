# team-storm
> Summary: workflow snags met fixing the team_reads_member_thing storm.

- The issue's lead (`w.snaps` lacking the cover) was a symptom: the snaps followed entries that went `Unknown` and stayed so. Tracing entry set/drop in `State::set_entry_fed` with a backtrace found the cause in minutes; a by-hand trace hook for one blob's entry life would save the next session that rebuild.
- Building the default reproducer took most of the time: `hold_blobs` stalls a node's whole host stream (the held push is never Applied), and `hide_blobs` on a writer makes it place again what it never heard of, a storm of the harness's making. A reader with `hide_blobs` and the missing record given by hand works.
