# signal-fire
- held.rs maps `IN` aspects to model names by index + 1, colliding with held-model's fixed names (8 `REQUIRED`, 9 `purge.0`, 10 `ADDENDA`) at the eighth entry; the clash showed only as a tier-2 validity difference. Now skipped explicitly; a named table would be safer.
- `arrival_order_addenda_small` runs on hand-picked seeds (35..42, "carry addenda"): any change to `random_step`'s draws flips its floor, so new steps go in their own generator.
- A tier-2 order run from a random offset hit an unrelated settled failure (issues/settled-order-551505.md).
- Review: the order harness collects a peer's commits only when that peer acts, so an addendum written during a `Sync` joins the history only at its writer's next step; a prelude meant to write one must end with a step by the witness.
- Review: building another revision's binary (`tools/bin-at`) at load 40 took 10 to 39 min.
