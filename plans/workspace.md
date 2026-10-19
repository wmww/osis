# Workspace, architecture and foundation crate
> Summary: Create the Cargo workspace and every crate skeleton (so the members list never conflicts), move the two models, write notes/architecture.md (crate map and DAG, the big abstractions and their traits, error-handling strategy, build and test performance rules, dependency policy, conventions), and implement `osis-core`: Value, canonical CBOR, Tid, Ak, Link, time types, format constants, chunker, hashing, the shared plug traits. First plan to run; everything else builds on it.
> Tags: data-model, tests

Crate: `osis-core` (plus skeletons of all others). Depends on: nothing. Unblocks: every other plan.
Spec: spec/data-model.md §1–§7, spec/versioning.md §1, spec/crdt.md §8 (chunker parameters), spec/overview.md conventions. Notes: notes/data-model.md, notes/local-store.md, notes/networking.md, plans/testing.md (layout). Spec trumps this plan.

## 1. Layout to create
```
Cargo.toml                 workspace, resolver 2, [workspace.dependencies], [workspace.lints], profiles (§4)
.cargo/config.toml         test env defaults (§4), optional fast linker
crates/osis-core           this plan
crates/osis-crypto         plans/crypto.md
crates/osis-crdt           plans/crdt-core.md, plans/crdt-seq.md
crates/osis-schema         plans/schema.md
crates/osis-commit         plans/commit.md
crates/osis-label          plans/label.md, plans/large-values.md
crates/osis-perm           plans/perm.md
crates/osis-keys           plans/keys.md
crates/osis-store          plans/store.md
crates/osis-proto          plans/proto.md
crates/osis-transport      plans/transport.md, plans/p2p.md
crates/osis-server         plans/server.md
crates/osis-node           plans/node-core.md, plans/node-sync.md, plans/membership-flows.md
crates/osis                plans/api.md (public API; the only crate apps depend on)
crates/osis-cli            plans/cli.md
models/crdt                git mv from crdt-model/ (keep history)
models/membership          git mv from tools/fixpoint/ (drop its own [workspace])
vectors/                   plans/test-infra.md (runner crate `osis-vectors`)
sim/                       plans/sim.md (crate `osis-sim`)
fuzz/                      plans/test-infra.md (cargo-fuzz; not a default member)
examples/                  plans/apps-e2e.md (own crates, default members so they stay compiling)
```
Every skeleton: `Cargo.toml`, `src/lib.rs` with `#![forbid(unsafe_code)]`, a doc comment naming its plan and its layer. `cargo test --workspace` passes after this plan.

## 2. notes/architecture.md: the big abstractions (write them down; agents code against these)
Each is a trait (or small trait family) in the crate named, with an in-memory or no-op implementation in the same crate for tests. Layers above never reach around them. Reopen only through an issue.
- **Layer DAG** (each crate depends only on crates in earlier layers, not necessarily on all of them): core; crypto, crdt, perm (each on core only); schema (core, crdt); commit (core, crypto, crdt, schema), keys (core, crypto, schema, perm), label (core, crypto, commit); store (core, crypto), proto (core, label); transport (core), server (label, proto, store, transport), node (everything below); osis (node), cli (osis, schema, server). perm consumes abstract edge-write records, not commit headers. Downward dependencies only; no crate depends on `osis` or `osis-node` except cli, sim, examples.
- **Sync vs async boundary**: core, crypto, crdt, schema, commit, label, perm, keys, proto, store are synchronous, do no I/O of their own, spawn no threads and take randomness (`&mut dyn CryptoRngCore`) and time (`Clock`) as parameters. They are deterministic under the simulator and wasm-friendly. tokio appears only in transport, server, node, osis, cli, sim.
- **`Backend` (osis-store)**: the storage engine abstraction. A transactional key-value store of opaque bytes: ordered keys, get/put/delete, prefix scan, atomic write batches, durable commit, plus a separate large-blob area (ciphertext files by BlobId). It never sees plaintext (notes/local-store.md). Implementations: `MemoryBackend` (tests, sim, with crash simulation), one file backend (store plan picks redb or rusqlite by build time and simplicity; pure Rust preferred). Everything above talks to `Store`, the encrypted-unit layer built on `Backend`; node never touches `Backend`.
- **`Transport` (osis-transport)**: `dial(Address) -> Connection`, `listen(Config) -> incoming Connections`; a `Connection` yields ordered, bidirectional, confidential byte streams with the authenticated peer's static public key and a close. Nothing in proto, node or server names QUIC, TCP or iroh. Implementations: `InProcess` (sim; deterministic, fault-injectable), QUIC with a pinned server key (transport plan), iroh (p2p plan). Framing of messages onto a stream is proto's job.
- **Sans-I/O protocol engines (osis-proto)**: the sync protocol (client side and server side) is a pair of state machines: `handle(Input) -> Vec<Output>` where inputs are decoded messages, timer fires and local events, outputs are messages to send, storage requests and timers. transport/node/server are thin drivers. This is what makes the simulator run real protocol code without tokio.
- **The node's sync layer is sans-I/O too** (plans/node-sync.md): everything in `osis-node` that reacts to messages, timers or engine events is a synchronous state machine (`SyncEngine::handle(Event) -> Vec<Action>` over the proto sessions, labeling and flows), with exactly two drivers: the tokio driver in `osis-node` (sockets, real timers) and the simulator's step driver (plans/sim.md), which delivers proto messages engine-to-engine under a seeded scheduler and virtual clocks. The simulator never runs tokio and never goes through the async transport; `InProcess` exists to test the drivers and the stream layer. Determinism is a property of this split, so reopening it is an issue.
- **`Clock`** (core): `now_wall_ms()`; node builds the HLC and the corrected clock on it. **Rng**: `rand_core::CryptoRngCore` passed in, never a global.
- **`View`** (crdt defines, schema implements): projection of read values onto what the writer's schema can type, used by the structural diff (spec/crdt.md §9).
- **`PageSink` / `PageSource` and `BlobFetch`** (crdt defines the first two, label implements with node): writes pages of a paged fragment (any delta or snapshot) as blobs and returns links; fetches pages (all of them before the commit applies) and chunks and tree nodes (lazily) by link.
- **Engine events** (node): the engine emits typed events (commit applied with its changed `(tid, ak)` set, origin, author, `ts`, receipt time; roster change; signal; sync status; diagnostic) on a channel after durability and outside its locks; the `osis` API builds watches on it (plans/node-core.md). The API never reaches into engine internals. The data API above is synchronous (notes/api.md, Design rules): node exposes blocking reads and writes, and async only where another node is waited on.
- **Held-set queries for perm** (node implements perm's traits): perm asks "edge writes held for thing N", "roster snapshots held", "/created of N", rather than holding state itself.

## 3. notes/architecture.md: error handling and pervasive rules
- Three error classes, kept distinct in every crate's `Error` enum: **BadInput** (peer or stored data violates the format or a rule: reject, emit a diagnostic, never panic, never store), **Parked** (data this build cannot interpret: unknown version, encoding, tag, field, case, suite; store and relay as bytes, re-examine after upgrade; spec/versioning.md §2), **Local** (storage, I/O, bug-class failures: surfaced to the app, never attributed to a peer). A decoder error carries which class it is; the node maps classes to behaviour mechanically.
- No panics on data: library crates set `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing` to deny (allowed in tests and in cli/examples). `debug_assert!` is for internal invariants only. Every decoder and parser takes limits (`format` constants) and is fuzzed (plans/test-infra.md). Arithmetic on peer-supplied numbers is checked or saturating.
- Hand-written `Error` enums with `Display` and `std::error::Error` (a tiny `impl_error!` macro in osis-core); no proc-macro dependencies in core-layer crates (compile time); `anyhow` only in cli and examples. The `osis` crate exposes one `Error` with stable categories (`NotFound`, `TypeMismatch{path}`, `Permission`, `Storage`, `Protocol`) wrapping the inner ones.
- Diagnostics are informational, structured (kind, tids, peer), rate-limited per peer and deduped (notes/api.md); correctness never depends on them being read.
- Determinism: seeded randomness only, injected clocks, in-process transport in tests; a failure is a seed.
- Secrets: zeroizing newtypes, redacted `Debug`, never in logs or error messages (errors name tids and blob IDs, never keys).
- Lints: `#![forbid(unsafe_code)]` in every crate; `cargo deny` for licences and duplicates (test-infra).

## 4. notes/architecture.md: build and test performance
Compile time and test time are the bottleneck of an agent-driven workflow. Rules:
- **Narrow crates, narrow deps**: a crate pulls only what its layer needs; heavy deps are feature-gated and off by default where a lower layer might otherwise compile them (`osis-transport`: `quic`, `iroh` features; `osis-store`: `file-backend` feature; `osis-server`: `bin` feature for the binary). `cargo test -p osis-crdt` must not build tokio, quinn, redb or ML-KEM.
- **Dependency policy**: allowlist in notes/architecture.md, one line per crate saying why; adding a dependency means adding its line. Start: blake3, ed25519-dalek, x25519-dalek, libcrux-ml-kem or ml-kem (crypto plan decides), chacha20poly1305, zeroize, rand_core + getrandom, tokio (node layer only), quinn + rustls (feature-gated; transport plan may choose a lighter pure-Rust option and record why), redb or rusqlite (feature-gated), proptest, criterion, arbitrary + libfuzzer-sys (fuzz only), iroh (feature-gated, p2p plan), clap (cli only). No serde, no CBOR crates, no parser generators, no proc-macro crates in core-layer crates.
- **Profiles**: `[profile.dev] debug = "line-tables-only"`, `[profile.dev.package."*"] opt-level = 2` (crypto and CBOR in debug are the slow part of tests), `[profile.test]` inherits dev, `[profile.release] codegen-units = 16, lto = "thin"`. `.cargo/config.toml` may select `lld`/`mold` if present (do not require it). Keep `incremental` on for dev.
- **Test tiers**: (1) fast: unit and small property tests (`PROPTEST_CASES` default 32 via `.cargo/config.toml` env, a crate's full fast tier under ~10 s); (2) slow: large property runs, differential runs at size, size budgets: `#[ignore]` and run with `--ignored` or `OSIS_SLOW=1`; (3) nightly: fuzz, simulator seed sweeps, big model instances (test-infra). Tests in tier 1 never sleep and never touch the network; disk only through a temp directory in osis-store's own backend tests (everything else uses MemoryBackend and InProcess).
- **Targeted runs**: an agent working in crate X runs `cargo test -p X` while iterating, then `cargo test -p X -p <direct dependents>` before committing; `cargo test --workspace` is the integration step (plans/mvp_meta.md), not the inner loop. Models are dev-dependencies of the crates they check only.
- Prefer `cargo nextest` when installed (per-test processes, parallel); plain `cargo test` must still work.
- Integration crates (sim, examples, cli) sit at the top of the DAG so no library build pulls them.

## 5. `osis-core` deliverables
- `Value`: Int(i64), Float(bits; canonical NaN at construction), Bool, Str, Bytes, Tid, Enum(case, Option<Box<Value>>), Map (sorted by canonical key bytes; also the struct representation with int keys), List, Set (sorted, unique by canonical bytes), Link, Unknown(tag, raw canonical bytes). `Ord`/`Eq` by canonical bytes.
- Canonical encoder and strict decoder for the §5 profile: shortest heads, definite lengths, sorted unique map keys, 8-byte floats only, canonical NaN only, no null/undefined/other simples, tags TID/ENUM/LINK (numbers from `format`, provisional until plans/protocol-spec.md fixes them), unknown tags preserved as raw bytes, everything else `BadInput`. Iterative or depth-capped, size-capped. Bytes kept as received (`CanonicalBytes` wrapper; decode returns the consumed slice), never re-encoded.
- `Tid`: 120 bits over the creation record (layout provisional, one function), text form 20 chars base64url, `osis://` parse/print; `Ak` validation (slash segments; one segment = core); `Link` (97-byte payload) under tag LINK; `BlobId`, `CommitId`, `LabelId`, `SchemaId`, `WallMs`, `Ts` (`wall_ms(ts)`, `make`), `Role` (read < write < admin).
- `format`: every constant with its spec name and fixed/provisional marker (`MAX_BLOB`, `CHUNK_THRESHOLD`, `PAGE_TARGET`, `MAX_DRIFT`, `MEMBERSHIP_KEEP`, `INBOX_LIFETIME`, `TOMBSTONE_LIFETIME`, heartbeat bounds, format version, decoder limits).
- Chunker: incremental gear-hash CDC (parameters in `format`), shared by large values and paging.
- Hash wrappers (BLAKE3 hash, keyed hash, derive_key); `Clock` trait with a `ManualClock`; `impl_error!`.

## Steps
- [x] Workspace, profiles, lints, skeletons, `git mv` of models (their tests pass from the new paths; notes/crdt.md and notes/permissions.md paths updated).
- [ ] notes/architecture.md with §2–§4 above plus the crate map; notes/overview.md updated (code layout, plans index).
- [ ] `osis-core` Value + CBOR: proptest round trip, canonical re-encode identity, each rejection rule as a negative test, mutation test (never panics).
- [ ] Tid/Ak/Link/ids, `format`, chunker (boundaries depend only on content; min/max honoured; equal inputs give equal chunks; incremental equals one-shot), hashing, Clock, error macro.
- [ ] CI skeleton `.github/workflows/ci.yml` (build, test tier 1, clippy, deny); plans/test-infra.md extends it.

## Done when
`cargo test --workspace` and `cargo clippy --workspace -- -D warnings` pass; `cargo test -p osis-core` builds nothing beyond blake3 and dev-deps; notes/architecture.md complete. Fold this plan into notes/architecture.md and delete it.

## Progress
