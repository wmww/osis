# Fuzzing

cargo-fuzz targets for every parser of bytes that can come from a peer or from disk. Outside the workspace (needs nightly and libFuzzer); nothing in tier 1 depends on it.

## Running
```
cd core/test/fuzz
cargo +nightly fuzz run --fuzz-dir . <target> /tmp/fz-<target> corpus/<target> -- -max_total_time=60
```
Every `cargo fuzz` command here takes `--fuzz-dir .` (otherwise cargo-fuzz looks for `fuzz/` at the repository root). The first directory receives new inputs (keep it out of the repo); `corpus/<target>` is the committed seed corpus, read-only. Smoke run: `-- -runs=1000`. List targets: `cargo +nightly fuzz list --fuzz-dir .`. Coverage of a target: `cargo +nightly fuzz coverage --fuzz-dir . <target> corpus/<target>`.

Seeds come from the vectors: `cargo run -p osis-vectors --bin gen-vectors -- corpus` replaces each target directory of `corpus/` (osis-vectors `corpus.rs`; seeds added by hand are lost, add them there). Keep corpora small; never commit `artifacts/` or a minimized run's output.

## A crash
1. Reproduce: `cargo +nightly fuzz run --fuzz-dir . <target> artifacts/<target>/crash-...`.
2. Fix it in the owning crate and add a regression test there with the input as a hex literal, citing the spec section and `fuzz: <target>`.
3. If the input is a useful seed, add it as a vector case (preferred) or to `corpus.rs`.

## Targets
Each target asserts no panic plus the parser's round-trip or consistency property.

| target | parser | crate | status |
|---|---|---|---|
| `cbor_decode` | value decoder, `CanonicalBytes`, `decode_prefix` | osis-base | live |
| `tid_parse` | tid text form | osis-base | live |
| `creation_record` | creation record read | osis-base | live |
| `chunker` | chunker bounds, incremental = one-shot | osis-base | live |
| `blob_prefix` | blob prefix, unpad | osis-label, osis-crypto | live |
| `commit_header` | commit header, commit blob plaintext | osis-commit | live |
| `delta` | delta and snapshot decoders (writer, snapshot, import forms), read and join of what decodes | osis-crdt | live |
| `seq_follow` | text writer deltas joined into a fixed text with range records; the cached placement's read equals a whole pass's (snapshot round trip) | osis-crdt | live |
| `seq_ops` | `arbitrary` op scripts on three replicas of a text or list (local ops, several per commit, skewed clocks; model commits; undos; joins in any order with duplicates; snapshot round trips and bootstraps) replayed by `osis_crdt::fuzzing::replay`: against crdt-model (state, read, delta bytes), a plain sequence, one-by-one commits, the wire, placements held in part, the crate's debug comparisons; no committed corpus | osis-crdt (`--cfg fuzzing`) | live |
| `join` | `arbitrary` states, join laws | osis-crdt | planned |
| `page` | page and link page | osis-crdt, osis-label | planned |
| `box` | sealed, `/secrets`, symmetric and history box openers, wrap, blob decrypt, unpad (fixed keys); `/secrets` and `/keys` value decoders | osis-crypto, osis-schema | live |
| `step` | step, claim set | osis-label | live |
| `inbox` | inbox payload | osis-label | live |
| `link_card` | link and card, text forms | osis-label | live |
| `proto_frame` | frame codec, Hello, each message | osis-proto | live |
| `bundle` | bundle reader, importer | osis-label | live |
| `schema_dsl` | schema DSL parser, schema-as-data | osis-schema | live |

## `seq_ops`
Its inputs are op scripts (`arbitrary`); libFuzzer's length control keeps them short (a few steps) for minutes, so for long histories add `-max_len=512 -len_control=0`. A crash's script: `cargo +nightly fuzz fmt --fuzz-dir . seq_ops <artifact>` prints it; paste it into a `fuzz_seq` test as a `Script` literal (or reproduce with `fuzz_seq::tests::shrink_script`, notes/testing.md). First run, 600 s on a loaded 16-thread laptop: 129k scripts (700/s at first, 215/s on average as scripts grew), coverage 149 → 10,000 edges in about a minute, 12,800 at the end, 2,000 corpus units, no crash.

## Adding a target
In the plan step that lands the parser: add `fuzz_targets/<target>.rs` and its `[[bin]]` in `Cargo.toml` (path dependency on the crate), its seeds in osis-vectors `corpus.rs`, run `gen-vectors corpus`, flip its row here to live, and smoke-run it with `-- -runs=1000`. The nightly workflow fuzzes every target `cargo fuzz list` prints.
