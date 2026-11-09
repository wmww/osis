# Each heartbeat leaves a `seen.0` commit and leftover forever
> Summary: A node's expiring `seen.0` commit stays after expiry as a commit row and a `w/` leftover row (about 580 B per heartbeat, +1 commit and +2 rows net in `growth`'s month steps, no writes): unbounded with time, not bounded by anything. `growth::single_writer_replace_grows_nothing` hides it behind a "month alone" control.
> Priority: normal
> Tags: engine, node, growth

Found reviewing zero-growth-1: a node with no writes, advanced 6 x 32 days, adds per step one `c/` commit and one `w/...seen.0...` leftover (13 commits after 6 steps, rows 69 to 79). `x/` timers and `y/` rows roll over, the rest stays. An expired leftover drops only under a cover (`retention::expired_leftover`), and an expiring commit is never an own replace (`snapshot::plain_held`), so nothing covers these. Real rate is one per heartbeat (interval from `HEARTBEAT_MIN_INTERVAL_MS`), so this is faster than the month step shows.
Fix options: a heartbeat replaced by the node's own next one drops and is forgotten once expired; or no durable commit for `seen.0`. Then tighten the growth test: no control term.
