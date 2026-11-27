# sheave-r3b-told
> Summary: workflow snags in the R3b notices job.

- A new push message kind needs four unrelated edits found only by failing tests: proto `msg.rs` (kind, flow, encode/decode), `msg/tests.rs` KINDS, proto `tests/it/differential.rs` (layout and the push-kind list), and osis-sync `session.rs` `Incoming::to` (an unrouted push silently closes the connection: a reconnect storm, not an error). One table of kinds would prevent it; at least `Incoming::to` should fail loudly on a kind `flow` knows.
- A dial hint to a peer no node answers storms the harness (2000 deliveries) instead of backing off: cost a detour writing the dial-hint test.
- Several count-based osis-sync tests pass alone and fail in the full run (`read::a_start_after_a_session_finds_nothing_owed_*`); `tools/ignores.py --run` reports them passing, so un-ignoring by its verdict lands a failing test.
