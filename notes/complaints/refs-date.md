# refs-date
> Summary: Footguns met fixing a slots presence-write date mismatch.

- The `whole_date` assert prints only the two dates. A temporary dump of the part, its winners with their held superseders, the state and every held body at the assert found the shape in one replay; reducing the world by hand was unnecessary. That dump on failure would be worth keeping.
- The from-scratch winners check (`tests_winners::beats`) already said a lower `W` at a `Slots` position is beaten; its proptests never generate two composite encodings written without a reset at one position, so it never saw the state disagree.
- `retention::oracle` is `cfg(test)`, so debug-build instrumentation in `bounds.rs` cannot call it.
