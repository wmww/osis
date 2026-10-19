# Testing
> Summary: How osis is tested and how to run each layer: principles, tiers and CI, conformance vectors and their freeze policy, fuzzing, size budgets and benches, coverage, policy checks, the spec-to-test map, and the conventions every crate follows when it adds tests, vectors, fuzz targets or benches.

Strategy items not yet built (differential tests, simulator, security suites, app-level tests) stay in plans/testing.md until they land.

## Principles
- The spec is the oracle: every MUST has a test that fails without it, and every test cites the spec section it checks, so `grep` (or notes/testing-map.md) answers "what checks §X".
- Determinism: seeded randomness, injected clocks, in-process transport. A failure is a seed; a flake is a bug.
- Peer bytes never panic: every parser is fuzzed; decoders take limits.
- Models (models/) are independent oracles; the implementation never depends on them and they are never patched to match it.

## Tiers and CI
| tier | what | how | where |
|---|---|---|---|
| 1 | unit, small proptest (`PROPTEST_CASES=32`), vectors | `cargo test -p <crate>`; `cargo test --workspace` at integration | `ci.yml`, every push |
| 2 | `#[ignore]` tests: large property runs, size budgets, differential at size | `OSIS_SLOW=1 PROPTEST_CASES=1024 cargo test --workspace --release -- --include-ignored` | `nightly.yml` `slow` |
| 3 | fuzz, sim seed sweeps, big model instances, TLC, benches, coverage | see below | `nightly.yml` |

`ci.yml` jobs: `test` (build, tier 1, vectors, clippy `-D warnings`), `policy` (tools/policy.py, `tools/spec_map.py --uncited`), `deny`. Nothing requires nextest, nightly or cargo-fuzz; nextest works if installed. Tier 1 never sleeps or touches the network. `nightly.yml` uploads proptest regressions, fuzz crash inputs and failing sim seeds as artifacts; its `sim-sweep` step is a placeholder until plans/sim.md adds `sim/src/bin/sim-sweep.rs`; its TLC step runs `models/tla/run.sh small` once plans/tla-models.md adds the script (below).

## Models (models/)
- `models/crdt` and `models/membership`: Rust reference models (notes/crdt.md, notes/permissions.md); the membership model's exhaustive tiers and random samples run in nightly `models`.
- `models/tla/sync` and `models/tla/rotation`: TLA+ models written from spec/ alone (plans/tla-models.md), checked with TLC. Sync covers one label at one blind server: upload, download, deposit and promotion, token and timed deletes, expiry, compaction, purge and rewrite, tombstones, offline nodes, a dropping/replaying/reordering server; properties: no live write leaves the label uncarried, must-hold bodies converge to the server, must-not-hold bodies and duplicates do not persist, entries settle, deposits get promoted, purges reach every node. Rotation covers read-role rotation of one actor: forced and eager rotation, forks, removal, registration steps, claims and claim-set drops, stranded heartbeats, re-seal by inbox; properties: no departed member reads content written with its departure known, no departed member holds an epoch that did not box it, every current member eventually opens every current epoch and reads everything. Each README gives the run command (TLC jar downloaded to `~/.cache/tla`, never vendored), the instances and their state counts and times.
- **CI decision**: TLC runs nightly, not per push (Java plus a jar download, tens of seconds to minutes per instance). Nightly `models` runs `models/tla/run.sh small`: every instance that checks clean in under about a minute on the CI runner (today `sync/deposit.cfg` and `rotation/MC_live.cfg`; the four counterexample instances join once the models are updated to the fixed spec text and pass). `run.sh all` runs the larger instances (5 to 20 minutes each) by hand. The script fails the job on any violated property or a failed download.
- **Not covered by the TLA+ models**: several labels or servers, projections and certificate copies, retagging, parked bodies and unfetched pages, clock skew, range reconciliation details, token levels, `nobody`/`admin`/`author` purge rights; write and admin rotation, keysets and departures inside a member, grants after epoch 0, demotion and `until`, step-tree branches, steps without rotation, entry boxes and key actors, `/label` compaction. The models are oracles for the spec, never patched to match code; a spec change that touches their sections re-runs them (plans/tla-models.md lists what the last round of edits changes).

## Conformance vectors (vectors/, crate osis-vectors)
- Format, subjects and rule IDs: vectors/README.md (language-neutral, ships with the spec). `.vec` text files of `key: value` records; every case has `case` and `spec`; `pending: <reason>` marks a case not yet checked.
- `vectors/MANIFEST` lists every file required by plans/test-infra.md: `pending` (crate not landed), `provisional`, or `frozen <blake3> <FC-n>`. A frozen file changes only with a `## FC-n` entry in vectors/FORMAT_CHANGES.md naming it (toplevel review) and `gen-vectors freeze <path> FC-n`; the `manifest_policy` test enforces this.
- Generated files (all but `cbor/` and `padme/`) must equal a fresh `cargo run -p osis-vectors --bin gen-vectors`; hand-written files have a checker that re-derives each case. Fixed inputs: seeds are 32 repeated bytes, randomness injected (plans/test-infra.md, "Vectors required").
- State: `cbor/values.vec` (hand-written), `tid/thing.vec`, `chunker/gear.vec` frozen (FC-1; chunker boundaries cross-checked by an independent Python implementation of spec/wire.md §6). Provisional, awaiting toplevel freeze: `padme/padme.vec` (hand-written), `tid/key-actor.vec`, `kdf/`, `keys/`, `box/`, `wrap/`, `token/`, `sign/` (osis-crypto), `commit/headers.vec` (osis-commit). Every other file pending its crate.

## Fuzzing (fuzz/, outside the workspace)
fuzz/README.md: running, the target table (live and planned per crate), crash handling. Seeds come from the vectors via `gen-vectors corpus` (osis-vectors `corpus.rs`). Nightly fuzzes every target `cargo fuzz list` prints for `fuzz_seconds` (default 300). Never commit `fuzz/artifacts/` or run output; corpora stay small.

## Size budgets and benches (crates/osis-bench)
- Budgets: `crates/osis-bench/tests/budgets.rs`, each `#[test] #[ignore] fn budget_<name>()` calling `assert_budget(name, actual, budget)` with the source number plus a margin (about 10%), citing its source. They use public APIs only (osis-bench is layer 9 and may depend on any crate).
- Live: `budget_creation_record`, `budget_minimal_commit` (commit blob plaintext of a header plus one register delta: 288 B against about 300, notes/crdt.md Commit floor).
- Pending budgets (add when the crate lands): removal from an N-member roster (no source number yet: set it from the first measurement); roster snapshot of N members, membership boxes about 1.2 KB per member and role (notes/crypto.md); revoke frontier after a long tenure (osis-perm, osis-commit); text of M chars after K edits, `text_bench` ratios of notes/crdt.md, Text size (osis-crdt).
- Benches: `crates/osis-bench/benches/<crate>.rs` with `harness = false`, calling `osis_bench::bench(name, bytes, f)` (prints median ns/iter and MB/s; `OSIS_BENCH_MS` sets the sample time). Run `cargo bench -p osis-bench`; nightly records the output as an artifact. Not gated. No criterion: a 40-line harness keeps the dependency tree and builds small.

## Coverage
Nightly `coverage` job: `cargo llvm-cov --workspace`, lcov and summary as artifacts, `continue-on-error`. Measured, never gated; read it for untested decoder branches. Locally: `cargo llvm-cov -p <crate>` if cargo-llvm-cov is installed.

## Policy checks
- `python3 tools/policy.py`: every workspace member has `[lints] workspace = true` (models: `[lints.rust] unsafe_code = "forbid"`), every crate root under crates/, vectors/, sim/ has `#![forbid(unsafe_code)]`, no `unsafe` block, fn, impl or trait anywhere in the workspace, and every external dependency has a backticked line in notes/architecture.md §5. fuzz/ is exempt (libfuzzer's macro uses `unsafe`).
- `cargo deny check` (deny.toml): licence allowlist (MIT, Apache-2.0, BSD, ISC, Zlib, CC0, Unicode-3.0), duplicate versions denied (a forced duplicate gets a `skip` with a reason), advisories, crates.io only. Members are `publish = false`.

## Spec-to-test map
`python3 tools/spec_map.py` writes notes/testing-map.md: per numbered spec section, the tests and live vector cases citing it, then gaps and uncited tests. Regenerate at integration (it is not checked for freshness in CI, since concurrent branches would conflict on it); `--check` tests freshness, `--uncited` (CI) fails on a test in crates/, vectors/ or sim/ that cites nothing. Gaps are treated like issues by hardening-signoff.

## Conventions for every crate
- **Spec citations**: put `// spec/<file>.md §N[.M]: <what>` right above each `#[test]` (inside `proptest!` too); a bare `§N` refers to the last file named in that comment. A test without its own citation inherits the file's `//!` header citations. Infrastructure tests with no spec section say `// spec: none (<why>)`.
- **Tiers**: tier-2 tests are `#[ignore]` (optionally also gated on `OSIS_SLOW=1`); a crate's tier 1 stays under about 10 s.
- **Vectors**: in the plan step that lands an encoding: write a generator `fn() -> VecFile` in `vectors/src/subjects/<subject>.rs` from the fixed inputs of plans/test-infra.md, register it in `subjects::get`, add the crate as an osis-vectors dependency, flip the MANIFEST line to `provisional`, run `gen-vectors`, and add the file to `vector_files!` in vectors/tests/vectors.rs. Hand-written vectors get a checker instead. Rejections use rule IDs documented in vectors/README.md. Toplevel review freezes them (FC entry).
- **Fuzz**: a target per parser of peer or disk bytes (fuzz/README.md, "Adding a target"), seeds in `corpus.rs`; a crash becomes a regression test in the owning crate citing the spec section and `fuzz: <target>`.
- **Budgets and benches**: in osis-bench as above; a new external dependency for them needs its line in notes/architecture.md §5.
