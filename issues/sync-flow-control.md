# Sync has no send window: slow links redial forever
> Summary: Nodes and servers emit uploads, fetches and replies without any bound on bytes in flight; past `MAX_QUEUED` (node, 64 MiB) or `max_queued_bytes` (server, 32 MiB) not yet taken by the transport the connection closes as "slow", and `REQUEST_TIMEOUT_MS` (2 min) counts from when a request was queued, not from the last progress. A large upload or fetch on a slow link closes the connection and the redial repeats it.
> Tags: node, proto, server, transport

Found by the arbitrary-values audit (notes/arbitrary-values-table.md): these values only make the failure unlikely on fast links.

- `proto/client.rs` `upload`/`Fetch`: every batch of a command is sent at once (a `want` of 4096 IDs, each blob up to 8 MiB; a Fetch of many 1024-ID chunks, each reply up to 9 MiB).
- `node/sync/driver.rs` `Action::Send`: `LinkTx::send(bytes, MAX_QUEUED)` false closes the connection. Server `driver.rs` the same with `max_queued_bytes` for replies, so pipelined Fetch replies on a slow downlink close it too.
- `client.rs` Timer: the oldest pending request older than `REQUEST_TIMEOUT_MS` closes the session, whatever is still arriving. At 64 KB/s one 9 MiB reply takes 2.4 min.
- Transport `HANDSHAKE_TIMEOUT` 5 s / 10 s (provisional) has the same shape for very slow links, though it also bounds half-open handshakes.

Fix direction: a per-connection window of request bytes in flight (and of reply bytes asked for), so the queue cap is never reached by the node's own traffic; the request timeout measured from the request leaving the queue and reset by received bytes. The caps then only catch a peer that does not read. Test on the in-process transport with a throttled link.
