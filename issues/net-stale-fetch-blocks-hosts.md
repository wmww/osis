# A stale stream Fetch blocks host fetches; a host fetch blocks streams forever
> Summary: `stream_asked` stops counting a reader Fetch older than `STALL_TIMEOUT_MS` only for other streams. Host paths (`fetch_on`, `open_or_fetch`, fill, pass `busy`/`unsettled_sets`) go by `fetching()`, which counts every stream Fetch whatever its age, and `stream_asked` counts every host fetch whatever its age. So a co-reader trickling a body's Fetch holds the host fetch of that body (and passes waiting on it), and a host trickling a reply holds the body from every co-reader.
> Priority: normal
> Tags: security, node, sync

## The case
Node A shares L with hostile co-reader B and has L open at host H. B announces body x first; A asks B (`stream_fetch`), B trickles its oldest reply (the stall rule keeps the connection). H's fill skips x (`!self.fetching(&b)`, and pops it from the queue), `read_first`/`judging` see it as in flight: x waits for as long as B trickles unless another stream announces it. The mirror: a host fetch of x (`Conn::req.fetching`) out and trickled makes `stream_asked` true for every stream.

## Direction
One rule for "asked" across sources: a fetch out longer than the stall time counts as asked nowhere, for hosts and streams alike (record the ask time on host fetches too), and a wake at that time re-runs what waited (fills, passes). Check what a pass's `busy` should mean for a stale fetch.
