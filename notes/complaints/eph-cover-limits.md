# eph-cover-limits
- A test that loops inside `Net::run` (here: a cover rebuilt at every step) just looks hung for minutes: `settle(200_000)` gives no sign. Output piped through `grep | head` is block-buffered and lost on `timeout`; write to a file instead.
- No perf/gdb on the box to sample a spinning test; debugging meant temporary eprintlns.
- Review: `net.group` twice in one test (same fixed seed) leaves the first group unsynced with no error (its ephemeral writes silently never sent); `group_seeded` with distinct seeds works. Cost a debug round.
