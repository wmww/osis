# Fuzzing

cargo-fuzz targets for every parser of bytes that can come from a peer or from disk. Outside the workspace (needs nightly and libFuzzer); nothing in tier 1 depends on it.

## Running
```
cd fuzz
cargo +nightly fuzz run <target> /tmp/fz-<target> corpus/<target> -- -max_total_time=60
```
The first directory receives new inputs (keep it out of the repo); `corpus/<target>` is the committed seed corpus, read-only. Smoke run: `-- -runs=1000`. List targets: `cargo +nightly fuzz list`. Coverage of a target: `cargo +nightly fuzz coverage <target> corpus/<target>`.

Seeds come from the vectors: `cargo run -p osis-vectors --bin gen-vectors -- corpus` rewrites `corpus/` (osis-vectors `corpus.rs`). Keep corpora small; never commit `artifacts/` or a minimized run's output.

## A crash
1. Reproduce: `cargo +nightly fuzz run <target> artifacts/<target>/crash-...`.
2. Fix it in the owning crate and add a regression test there with the input as a hex literal, citing the spec section and `fuzz: <target>`.
3. If the input is a useful seed, add it as a vector case (preferred) or to `corpus.rs`.

## Targets
Each target asserts no panic plus the parser's round-trip or consistency property.

| target | parser | crate | status |
|---|---|---|---|
| `cbor_decode` | value decoder, `CanonicalBytes`, `decode_prefix` | osis-core | live |
| `tid_parse` | tid text form | osis-core | live |
| `creation_record` | creation record read | osis-core | live |
| `chunker` | chunker bounds, incremental = one-shot | osis-core | live |
| `blob_prefix` | blob prefix, unpad | osis-label, osis-crypto | planned |
| `commit_header` | commit header, commit blob plaintext | osis-commit | planned |
| `delta` | delta and snapshot decoders per encoding | osis-crdt | planned |
| `join` | `arbitrary` states, join laws | osis-crdt | planned |
| `page` | page and link page | osis-crdt, osis-label | planned |
| `box` | sealed box, `/secrets` box, history box, wrap | osis-crypto, osis-keys | planned |
| `step` | step, claim set | osis-label | planned |
| `inbox`, `signal` | inbox payload, signal envelope | osis-label | planned |
| `link_card` | link and card, text forms | osis-label | planned |
| `proto_frame` | frame codec, Hello, each message | osis-proto | planned |
| `bundle` | bundle reader | osis-label | planned |
| `schema_dsl` | schema DSL parser, schema-as-data | osis-schema | planned |

## Adding a target
In the plan step that lands the parser: add `fuzz_targets/<target>.rs` and its `[[bin]]` in `Cargo.toml` (path dependency on the crate), its seeds in osis-vectors `corpus.rs`, run `gen-vectors corpus`, flip its row here to live, and smoke-run it with `-- -runs=1000`. The nightly workflow fuzzes every target `cargo fuzz list` prints.
