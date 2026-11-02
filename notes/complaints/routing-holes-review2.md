# routing-holes-review2
> Summary: Mishaps met on the second routing-holes review.

- A filtered `cargo test --workspace --test it -- name` prints a `test result: ok. 0 passed` per crate: read the line for the crate that ran it, not the last one.
- `after_route` fires at a growing number of points; a test counting its calls (the grant one) has to know them.
