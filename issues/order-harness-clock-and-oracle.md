# The order harness delivers at the final clock and judges deaths with the engine's own replay
> Summary: `core/node/tests/it/order.rs` delivers every commit at the final clock time, so state that changes when an expiry passes or a request arrives mid-history is never exercised (the order-seeds-c review found a divergence this way: a node holding the history before an expiry vs one receiving it after). Its death check calls the engine's `replay_deaths` → `replay_all`, so a bug there agrees with itself.
> Tags: tests, engine

Wanted: a mode that delivers a prefix at an earlier clock, then advances it and delivers the rest, compared with all-at-the-end; and a death oracle independent of `retention::deaths::replay_all` (the 52040 test asserts the body drop directly, which is the shape to follow).
