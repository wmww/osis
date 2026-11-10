# A host trickling a fill's order-0 batch holds every pass of the label
> Summary: a fill waits on its own batch whatever its age (`fill_more`: `f.asked.retain(fetching.contains_key)`), and `dirty_labels` runs no pass of a label while any connection's fill has not fetched order 0 (`fill_first_waits`). So a host trickling its reply to a fill's order-0 batch holds every pass of the label at every host, and the bodies of that batch: another host's fill skipped them while the fetch was fresh (`asked_for`, popped from its queue), and its `refetch` needs a pass.
> Priority: normal
> Tags: security, node, sync

## The case
Node A opens L at hosts H1 and H2 for the first time (both fill). H1 is asked order-0 body x first and trickles the reply (the stall rule keeps the connection). H2's fill reaches x while H1's fetch is fresh, skips and pops it. H1's fill never sets `first_done`, so no pass of L runs anywhere, and nothing fetches x from H2 (`refetch` runs in a pass, and not while H2 still fills). On main too: the `asked` rule (notes/peers.md, Bodies) covers fetch_on, fill, refetch and streams, not a fill's wait on its own batch.

A milder, bounded form with honest hosts: a body H2's fill skipped for a fresh fetch elsewhere waits for H2's fill to end (`refetch` returns while its own label fills), however long that fill is.

## Direction
Apply the one rule to the fill's own wait: a fill waits on its batch only while it counts as asked (`asked`), so a stale batch lets the fill go on (and `first_done` come) and the body is asked elsewhere; a body the fill skipped for a fresh fetch elsewhere stays queued (looked at again each batch) rather than popped. Test: two hosts filling, one trickling (`Net::trickle_hosts`), A reads by the stall time.
