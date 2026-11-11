# Connection memory beyond the hub's byte bound
> Summary: `max_buffered_bytes` bounds what the hub holds for its connections, not the transport's buffers per connection (about 6 MiB each, times `max_connections` 10 000); and the output half closes honest slow readers once about 15 full windows are unread at once.
> Priority: normal
> Tags: security, node, transport

## Transport buffers scale with the count
Per served connection, outside `Hub::buffered`/`Hub::unread`: the QUIC receive window (`CONN_WINDOW` 4 MiB, filled by any peer that sends while the hub waits for its turn), the link's read-ahead (`READ_AHEAD` 16 × `READ_CHUNK` 64 KiB = 1 MiB) and bytes `write_all` handed to quinn under the stream credit (`STREAM_WINDOW` 1 MiB). At the default `max_connections` that is up to about 60 GiB, reachable by anyone sharing one group (a public link) from enough sources. Ways out: count the read-ahead in the hub's in-direction (the driver knows it), size the transport windows from the memory bound over the connection count, or derive the default `max_connections` from the memory bound.

## Honest slow readers closed under load
An honest reader keeps up to its request window unread (`WINDOW_QUEUE` + a push, about 34 MiB) while its link drains, so about 15 slow readers pulling at once pass 512 MiB, and the one holding the most is closed and redials (bytes in flight wasted, partial frames lost), though it reads. A host serving many slow devices churns. Direction: back-pressure keeps the property without closing readers. While over the bound, give no input turns and no push room, so readers drain and resume; close the biggest holder only when its bytes are not moving (the bound is full of bytes nobody takes).
