# keep-after-removal review 3
> Summary: footguns met reviewing kept copies.

- `w.set_online(&b, true); w.run()` does not reconnect: status stays Unreachable until time moves (dial backoff); `w.advance(60_000)` first. A test's failure read as a product bug for a while.
- A rebase conflict on issues/order-seeds-found-on-main.md: every branch appending seeds there conflicts with any fix pruning it.
