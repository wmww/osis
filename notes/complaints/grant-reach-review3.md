# grant-reach-review3
> Summary: mishaps while re-reviewing grant-reach.
- `cargo test ... | grep` on a 40-seed probe outlived the 180 s foreground limit and moved to the background on its own; the probe file then held the log, fine, but a seed count that big belongs in `run_in_background` from the start.
- A probe by `seed(reader)` needs a reader who never read the thing's own label (issues/deposit-seed-reaches-departed.md): my first owned-holder probe failed for that known reason and looked like a new leak; a reader joining after the removal tells them apart.
- `db.engine` needs `osis::internals::Internals` in scope; the compiler's hint points at a private method instead.
