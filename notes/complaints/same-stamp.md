# same-stamp
- Order/walks oracles print their seed-range summary only with `--nocapture`; a passing run under plain `cargo test` shows just `1 passed`, so confirming the range took a second run.
- Debugging a failing osis-crdt proptest: the `Debug` dump of two states is one huge line; diffing needed a throwaway script. A test helper printing the first differing record would save time.
