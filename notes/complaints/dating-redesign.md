# dating-redesign
> Summary: slow spots and wrong turns met rebuilding retention dating on durable held writes.

- An `assert_eq!` of two row maps dumped 100 KB into the log on one failure: compare with `assert!(a == b)` and print the first few differing keys.
- `osis_base::cbor::decode_prefix` returns the bytes the value spans, not the rest: a reader advancing by the second item skipped nothing and failed far away as "source".
- The commits index journals a commit once per step (`Commits::log`), so a reader following the log by position misses a commit changed twice; `Commits::changes` lists every change.
- Tests with `page_max: 512` bound store keys at 128 B (`btree::check_key`): position paths in keys failed 38 tests with "table key too long" before they were hashed.
- A memory transaction keeps every row it writes in memory (`Tx::in_class`): durable rows written for a durable aspect inside one vanish at restart and leave half an index.
- `Fragment::approx_bytes` is memory, about ten times the encoded bytes: no measure for a wire size.
- The box ran at load 40-50 through the session: an engine `cargo test` took 9-10 minutes, a build after a crdt change 4-10 minutes.
