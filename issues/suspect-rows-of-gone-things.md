# Suspect repair rows of forgotten things stay
> Summary: a reporter's `I/s/` repair row stays until an entry of the same aspect shows it stale: rows of a thing since forgotten here, of a sync ID shredded here (the key names no S), and of a reporter account that never reports again all stay for the node's life; keying rows thing-first covers only the first.
> Priority: low
> Tags: sync

osis-sync `inbox/suspect.rs` keeps a row `I/s/ reporter thing ak` per (reporter account, aspect) repaired. It goes only when an entry shows it stale, so a thing forgotten here, a shred of S (the key holds no sync ID) and a reporter that lost read access and never reports again each leave rows behind. Bounded by S's reader accounts times the aspects this node ever repaired. Keying the rows thing-first lets the thing's forgetting drop them; the dead-reporter case needs its own end (e.g. the row dropped once the reporter no longer reads the thing, or the rows of a reporter dropped with its last record).
