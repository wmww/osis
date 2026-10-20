# Unauthenticated clients can hold a server's memory in partial frames
> Summary: A blind server buffers up to `MAX_MESSAGE` (9 MiB) of a declared frame per session before parsing it, Hello included, with up to `max_connections` (10 000) sessions: about 94 GB held by anyone who can connect; QUIC flow-control windows (18.9 MB per stream, 37.7 MB per connection) add to it when the hub lags.
> Tags: security, server, transport

Repro: by reading, not run: `osis-proto/src/frame.rs` (`FrameDecoder` holds a whole declared frame), `osis-server/src/hub.rs` (sessions capped, not buffered bytes), `osis-transport/src/quic.rs` `stream_receive_window`/`receive_window` (sized from `MAX_MESSAGE`; the comment that windows must hold a whole frame is wrong, the reader drains incrementally). A test: an in-process hub with `max_connections = 4`, clients each sending a frame header of `MAX_MESSAGE` and a slow body; assert buffered bytes stay under a budget.

- A Hello is at most about 200 bytes (spec/wire.md §11.1: 16 versions), so a first frame above 256 bytes is malformed: capping it before Hello is free, but Hello costs nothing to send, so it does not bound memory alone.
- Direction: a hub-wide budget of partially received frame bytes (closing the session with the largest partial frame when exceeded), `link::serve_max` with a connection cap on the server listener, smaller QUIC/iroh windows (1 MiB per stream, 4 MiB per connection); iroh: a handshake timeout on dial (`iroh.rs` `ep.connect`), a cap on concurrent handshakes, datagrams off and the idle timeout set as in `quic.rs`.
