# dead-set
- The crdt property tests run the committed seed unless `OSIS_CRDT_SEED` is set; a new property needs a few `OSIS_CRDT_SEED=n` runs by hand to see more than one sample.
- `history` (not `history_honest`) gives writers whose clocks run behind what they saw (a move older than the creation it moves); a check that needs honest clocks has to pick `history_honest`.
