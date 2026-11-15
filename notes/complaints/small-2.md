# small-2
- A Feed only sees keys written after it is made, so state loaded at a store's open cannot reach a reader through its feed; the raise-to-read restart needs `anew_feed` to read the durable marks and announce them to the feed it makes.
- `set_holdings` was infallible while the store under it is not; making it return `Result` touched 30 test call sites (`set_sync_set(..).unwrap()`).
- Review: the rebase onto a987ee295 conflicted in store rows (`DROPPED` renamed `ANEW` here, `FIRST` added upstream at the same lines); resolved by hand.
