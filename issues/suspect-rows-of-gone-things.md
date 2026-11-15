# Suspect repair rows of forgotten things stay
> Summary: a reporter's `I/s/` repair row of a thing since forgotten here stays until an entry of it shows the row stale; keying rows thing-first would let the thing's forgetting drop them.
> Priority: low
> Tags: sync

osis-sync `inbox/suspect.rs` keeps a row `I/s/ reporter thing ak` per (reporter account, aspect) repaired. It goes only when an entry shows it stale, so a thing forgotten here leaves its rows behind. Bounded by S's reader accounts times the aspects this node ever repaired. Fix: key the rows thing-first so the thing's forgetting drops them with it.
