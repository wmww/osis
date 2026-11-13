# The deletion-horizon listing tests do not isolate the trimmed listing
> Summary: `sync_more::a_listing_past_the_deletion_horizon_*` pass with the trimmed-listing deletion disabled: the reader drops v0 by its own judgment once it holds v5, or (v5's bytes withheld) places v0 again and the writer deletes it. They need an entry the reader cannot judge (another node's card, a role-class certificate) deleted at the host while it is away.
> Priority: low
> Tags: tests, node
