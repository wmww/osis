# parts-seeds-review
> Summary: Mishaps on the parts-seeds review.

- `cargo test --workspace --test it <filter> | tail` shows the last crate's empty run, and hides the one that ran: use `-p osis-node` for probe output.
- `CommitBuilder` sorts aspects: a probe slicing parts by aspect index cut the wrong thing and gave a false "applied"; slice by thing.
- An order seed through a filter on its failure text is 130 s; the 180 s bash cap moved a chain of them to the background mid-run.
