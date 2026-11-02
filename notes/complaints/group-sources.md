# group-sources
> Summary: What bit tiller-group-sources while building the client port's (d).

- `Value::uint` saturates at `i64::MAX`, silently: a flag at bit 63 of a nonce vanished on the wire (`NONCE_RESENT` is bit 62). `Value::try_uint` exists; `uint` looks like the safe one.
- In-process `net.partition` holds a connection silently; only `disconnect` too ends it: a test stalled 60 s on a stall timeout before this was clear.
- The first `cargo test -p osis sources::` moved to the background at 180 s, on one test stalled by the above; run with `timeout` and a thread cap while tests can hang.
- The port's methods tell `Unsupported` for a client's `wait_synced`, so moving a group home had to poll `status`.
- Review: `lost_reply_retried_applies_once` passed with replay disabled: a `set` of an equal value commits nothing, so commit counts cannot see a second run. Use a counter for exactly-once.
- Review 2: `sync_here` read `role_on` through the route, and the guard added to `persist` broke it on the way home; no test held a route with no label. `x.p.set_route` makes the state.
