# Message kinds in one table
> Summary: Adding a wire message kind takes four unrelated edits found only by failing tests (proto `msg.rs` kind/flow/codec, `msg/tests.rs` KINDS, proto `tests/it/differential.rs` layout and push list, osis-sync `session.rs` `Incoming::to`); an unrouted push kind silently closes the connection (a reconnect storm, not an error). One table of kinds should drive all four, and `Incoming::to` should fail loudly on a kind `flow` knows.
> Priority: low
> Tags: proto, sync
