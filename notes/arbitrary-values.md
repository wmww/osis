# Arbitrary values
> Summary: The owner's rule for thresholds, caps, grace periods, timeouts and other picked numbers: each needs a stated justification class, and the 0/infinity test must pass; a value that only makes a bug unlikely is a defect.

Every picked number in code or spec (threshold, cap, batch size, grace period, timeout, retry count, cache size) is judged by asking what happens at 0 and at infinity.

Acceptable classes:
- **Performance switch between correct strategies.** Strategy A scales badly, B is much faster at small n, both are correct and secure for every n. A threshold picks between them; its exact value only matters for speed (tuning is optional, the extremes must both be handled). First ask whether dropping one strategy is the simpler win because other costs on the path dominate.
- **Resource bound against hostile or runaway input.** Memory, CPU, message or path limits (DoS bounds). Exceeding it must give a defined, safe outcome (refuse, evict, close), tested.
- **Minor consequence.** The failure past the value is small enough (a little extra work, a slightly late erase) that a best guess is right; the consequence is stated next to the value.
- **Owner-agreed tradeoff.** A protocol constant where no value is free of cost (e.g. `MEMBERSHIP_KEEP` 90 days: how long membership history is kept for offline devices to sync cleanly; `MAX_DRIFT`; `AT_MOST_GRACE`). Recorded in the spec with the owner's sign-off.

Not acceptable: a value that turns likely incorrectness into unlikely incorrectness (a race window, a retry count that usually suffices, a timeout that usually covers the slow path, a cache that is usually big enough for correctness). If 0 or infinity breaks correctness or security, explain why the chosen value never does; if that cannot be argued, the code is wrong, not the number. Such values hide bugs until they show in the wild.

When adding a value: name it as a constant with a one-line comment giving its class and what 0 and infinity would do. The audit table (every value with its class, justification and the defects found): notes/arbitrary-values-table.md, the project's durable record of magic numbers; update its row in the same commit that adds, changes or removes a value (reviewers check it). Owner review of the tradeoff values: issues/magic-number-review.md.
