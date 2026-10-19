# Architecture
> Summary: The implementation's shape: crate map and layer DAG, the fixed abstractions (traits) other crates code against, error classes and pervasive rules, build and test performance rules, dependency allowlist, conventions, and the public surfaces of osis-core and osis-schema. Reopen a fixed item only through an issue.

## 1. Crate map
Workspace root `Cargo.toml`: members `crates/*`, `models/*`, `vectors`, `sim` (apps-e2e adds `examples/*`: an empty glob fails the build); `fuzz/` is excluded (cargo-fuzz). Internal crates are `[workspace.dependencies]`; members write `osis-core.workspace = true`. A new crate needs a line here.

| layer | crate | plan(s) | contents |
|---|---|---|---|
| 0 | `osis-core` | (this note, §7) | Value, canonical CBOR, Tid, Ak, Link, ids, time, `format` constants, chunker, hashing, `Clock`, `impl_error!` |
| 1 | `osis-crypto` | crypto | suite 1 primitives, kdf, sealed boxes, wraps, delete tokens |
| 1 | `osis-crdt` | crdt-core, crdt-seq | merge encodings, delta grammar, join/read/diff, paging; `View`, `PageSink`, `PageSource` |
| 1 | `osis-perm` | perm | membership validity rules over an abstract held set |
| 1 | `osis-transport` | transport, p2p | `Transport`; `InProcess`, QUIC (`quic`), iroh (`iroh`) |
| 2 | `osis-schema` | schema | DSL, types, core aspect types, implements `View` |
| 2 | `osis-store` | store | `Backend`, `MemoryBackend`, `RedbBackend` and `FileRoot` (`file-backend`), `RootStorage`, `Store`, `Transaction` |
| 3 | `osis-commit` | commit | commit header and blob, kinds, retention, tokens, signatures, builder, verification, projection, chunk trees of header lists (notes/crdt.md) |
| 3 | `osis-keys` | keys | keysets, epochs, boxes, history boxes, label keys |
| 4 | `osis-label` | label, large-values | blobs, labels, steps, stamps, chunk trees |
| 5 | `osis-proto` | proto | sans-I/O sync protocol engines |
| 6 | `osis-server` | server | blind node used as a server (`bin` feature for the binary) |
| 7 | `osis-node` | node-core, node-sync, membership-flows | engine, apply, retention, labeling, sync engine, flows |
| 8 | `osis` | api | public API; the only crate apps depend on |
| 9 | `osis-cli` | cli | binary `osis` |
| 9 | `osis-vectors` (`vectors/`) | test-infra | conformance vector format, runner, generator, freeze check, fuzz seed corpora |
| 9 | `osis-bench` | test-infra | bench harness (no deps) and benches; size budgets (tier 2) |
| 9 | `osis-sim` (`sim/`) | sim | deterministic simulator |
| 9 | `examples/*` | apps-e2e | example apps, default members so they keep compiling |
| - | `crdt-model` (`models/crdt`) | | reference model of spec/crdt.md (notes/crdt.md) |
| - | `membership-model` (`models/membership`) | | model of the membership rules (notes/permissions.md) |

**Layer DAG** (each crate depends only on crates in earlier layers, not necessarily all): core; crypto, crdt, perm, transport (core only); schema (core, crdt); store (core, crypto); commit (core, crypto, crdt, schema); keys (core, crypto, schema, perm); label (core, crypto, crdt, schema, commit: `PageSink`/`PageSource` impls, `/label` and `address` codecs); proto (core, label); server (core, crypto, label, proto, store, transport); node (everything below); osis (node); cli (osis, schema, server); sim (osis, node, server, store). perm consumes abstract edge-write records, not commit headers. No crate depends on `osis` or `osis-node` except cli, sim and examples. Models are dev-dependencies of the crates they check only, and use no workspace lints.

## 2. Fixed abstractions
Each is a trait (or small trait family) in the named crate with an in-memory or no-op implementation in the same crate for tests. Layers above never reach around them.
- **Sync vs async**: core, crypto, crdt, schema, commit, label, perm, keys, proto, store are synchronous, do no I/O of their own, spawn no threads, and take randomness (`&mut dyn CryptoRngCore`, rand_core) and time (`Clock`) as parameters: deterministic under the simulator, wasm-friendly. tokio appears only in transport, server, node, osis, cli, sim.
- **`Backend`** (osis-store): transactional KV of opaque bytes: ordered keys, get/put/delete, prefix scan, atomic write batches, durable commit, plus a large-blob area (ciphertext files by BlobId). Never sees plaintext (notes/local-store.md). `MemoryBackend` (tests, sim; crash simulation) and one file backend (redb, feature `file-backend`; notes/local-store.md, Implementation). Everything above talks to `Store`, the encrypted-unit layer on `Backend`; node never touches `Backend`.
- **`Transport`** (osis-transport): `dial(Address) -> Connection`, `listen(Config) -> incoming Connections`; a `Connection` yields ordered, bidirectional, confidential byte streams with the authenticated peer's static public key, and a close. Nothing in proto, node or server names QUIC, TCP or iroh. `InProcess` (deterministic, fault-injectable), QUIC with a pinned server key, iroh. Framing messages onto a stream is proto's job.
- **Sans-I/O protocol engines** (osis-proto): client and server sides of the sync protocol are state machines, `handle(Input) -> Vec<Output>`: inputs are decoded messages, timer fires, local events; outputs are messages, storage requests, timers. transport/node/server are thin drivers.
- **Node sync layer is sans-I/O** (plans/node-sync.md): everything in `osis-node` reacting to messages, timers or engine events is `SyncEngine::handle(Event) -> Vec<Action>` over proto sessions, labeling and flows, with exactly two drivers: the tokio driver in `osis-node` and the simulator's step driver (seeded scheduler, virtual clocks, engine-to-engine delivery; never tokio, never the async transport). `InProcess` tests the drivers and the stream layer. Determinism rests on this split.
- **`Clock`** (core): `now_wall_ms()`; node builds the HLC and the corrected clock on it. **Rng**: `rand_core::CryptoRngCore` passed in, never a global.
- **`View`** (crdt defines, schema implements): projection of read values onto what the writer's schema can type, for the structural diff (spec/crdt.md §9).
- **`PageSink` / `PageSource`, `BlobFetch`** (crdt defines the first two, label implements with node): write pages of a paged fragment (any delta or snapshot) as blobs and return links; fetch pages (all before the commit applies), chunks and tree nodes (lazily) by link. osis-commit's `BlobSink` / `BlobSource` (prefix inputs in, plaintext out; content hashes checked by commit) carry chunk trees of header lists.
- **Engine events** (node): typed events (commit applied with its changed `(tid, ak)` set, origin, author, `ts`, receipt time; roster change; signal; sync status; diagnostic) on a channel after durability and outside locks; the `osis` API builds watches on them and never reaches into engine internals. The data API is synchronous (notes/api.md): blocking reads and writes, async only where another node is waited on.
- **Held-set queries for perm** (node implements perm's traits `HeldSet` and `MoveIndex`): "edge writes held for thing N", "roster snapshots held", "/created of N", valid `/was` and `/moved` reads; perm holds no state (notes/permissions.md, Implementation).

## 3. Errors and pervasive rules
- Three error classes, distinct in every crate's `Error` enum: **BadInput** (peer or stored data violates the format or a rule: reject, diagnostic, never panic, never store), **Parked** (data this build cannot interpret: unknown version, encoding, tag, field, case, suite; store and relay as bytes, re-examine after upgrade; spec/versioning.md §2), **Local** (storage, I/O, bug class: surfaced to the app, never attributed to a peer). Every error reports its class (`osis_core::ErrorClass` via a `class()` method); the node maps classes to behaviour mechanically. Note: an unknown CBOR tag is not an error at all (it decodes to `Value::Unknown`); parking happens where a typed read fails.
- No panics on data: workspace lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` (clippy.toml allows them in tests; cli, examples, osis-vectors' library and gen-vectors allow them crate-wide). `debug_assert!` only for internal invariants. Every decoder takes limits (`format` constants) and is fuzzed. Arithmetic on peer-supplied numbers is checked or saturating.
- Hand-written `Error` enums with `Display` and `std::error::Error` via `osis_core::impl_error!`; no proc-macro dependencies in core-layer crates; `anyhow` only in cli and examples. `osis` exposes one `Error` with stable categories (`NotFound`, `TypeMismatch{path}`, `Permission`, `Storage`, `Protocol`) wrapping the inner ones.
- Diagnostics: informational, structured (kind, tids, peer), rate-limited per peer, deduped; correctness never depends on them.
- Determinism: seeded randomness, injected clocks, in-process transport in tests; a failure is a seed.
- Secrets: zeroizing newtypes, redacted `Debug`, never in logs or errors (errors name tids and blob IDs, never keys).
- `#![forbid(unsafe_code)]` in every crate (also the workspace lint); `cargo deny` for licences and duplicates (test-infra).

## 4. Build and test performance
Compile and test time are the bottleneck of agent-driven work.
- **Narrow crates, narrow deps**: heavy deps are feature-gated, off by default where a lower layer might compile them (`osis-transport`: `quic`, `iroh`; `osis-store`: `file-backend`; `osis-server`: `bin`). `cargo test -p osis-crdt` must not build tokio, quinn, redb or ML-KEM. `cargo test -p osis-core` builds blake3 and proptest only.
- **Profiles** (root Cargo.toml): dev `debug = "line-tables-only"`, all dependencies at `opt-level = 2`, test inherits dev, release `codegen-units = 16`, `lto = "thin"`, incremental on. `.cargo/config.toml` has a commented fast-linker line (mold/lld are not required).
- **Test tiers** (notes/testing.md): (1) fast: unit and small property tests, `PROPTEST_CASES=32` by default via `.cargo/config.toml` (an explicit env value wins), a crate's fast tier under ~10 s; (2) slow: large property runs, differential runs at size, size budgets: `#[ignore]`, run with `--ignored` (or gated on `OSIS_SLOW=1`); (3) nightly: fuzz, simulator seed sweeps, big model instances. Tier 1 never sleeps or touches the network; disk only through a temp directory in osis-store's own backend tests (everything else uses `MemoryBackend` and `InProcess`).
- **Targeted runs**: in crate X run `cargo test -p X` while iterating, `cargo test -p X -p <direct dependents>` before committing; `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` at integration.
- `cargo nextest` when installed; plain `cargo test` must work. Nothing may require nextest, deny or fuzz.
- Integration crates (sim, examples, cli) sit at the top so no library build pulls them.

## 5. Dependency allowlist
One line per external crate; adding a dependency means adding its line. No serde, no CBOR crates, no parser generators, no proc-macro crates in core-layer crates.
- `blake3` (core, crypto; `default-features = false, features = ["std"]`; crypto adds `zeroize`, which wipes kdf hasher state): the only hash (spec/crypto.md §1); crypto uses it directly for the kdf XOF and `SeededRng`.
- `ed25519-dalek` 2.2 (crypto; `std`, `zeroize`, `fast` (curve25519-dalek `precomputed-tables`); no `rand_core`/`batch`): Ed25519 with `verify_strict`, plus our canonical-encoding check on keys.
- `x25519-dalek` 2.0 (crypto; `static_secrets`, `zeroize`, `precomputed-tables`): X25519 with the contributory check.
- `libcrux-ml-kem` 0.0.11 (crypto; `mlkem768` only, no `rand` feature): ML-KEM-768. Chosen over RustCrypto `ml-kem` 0.3: keygen from the 64-byte `d || z` seed and encapsulation from 32 explicit bytes are plain array functions, and it is formally verified. Its `libcrux-traits` dependency still compiles `rand` 0.10 and `rand_core` 0.10 (no OS randomness, unused by us). Checked against NIST ACVP FIPS 203 answers (test `mlkem_fips203_acvp`).
- `chacha20poly1305` 0.10 (crypto; `alloc`): XChaCha20-Poly1305.
- `zeroize` 1.8 (crypto, transport): secret wipe on drop.
- `subtle` 2.6 (crypto; no default features; already in the tree via the dalek crates): `ConstantTimeEq` for `Secret32`.
- `rand_core` 0.6 (crypto; no default features; re-exported as `osis_crypto::{CryptoRngCore, RngCore, CryptoRng}`; other crates use the re-export): the injected-rng trait, the version the dalek 2.x crates use. `getrandom` comes only through osis-crypto's `os-rng` feature (`rand_core/getrandom`, `osis_crypto::OsRng`), for drivers; `cargo tree -p osis-store` has no getrandom.
- `proptest` (dev, all crates; models use their own version line): property tests.
- `libfuzzer-sys` (`fuzz/` only, outside the workspace): cargo-fuzz harness.
- `redb` 2.6 (store, feature `file-backend`; `default-features = false`): the file backend. Pure Rust, no C toolchain (rusqlite bundles SQLite: slower build, C), MSRV within ours; holds only ciphertext, so its engine never needs to erase (notes/local-store.md).
- `quinn` 0.11 (transport, feature `quic`; no default features, `runtime-tokio`, `rustls-ring`): QUIC for direct server connections (spec/sync.md §10). Chosen over Noise-over-TCP: native streams, flow control, keep-alive and connection migration, the same stack iroh builds on; the cost is build time, kept off default builds.
- `rustls` 0.23 (transport, feature `quic`; no default features, `ring`, `std`): TLS 1.3 with RFC 7250 raw Ed25519 public keys (no certificates, no rcgen/webpki roots); custom verifiers pin the server key.
- `ring` 0.17 (transport, feature `quic`; already rustls's provider): Ed25519 key pairs from the static seed, OS randomness for ephemeral client keys. Chosen over `aws-lc-rs` (needs cmake, slower build); ring compiles some C/asm with `cc` (not pure Rust; acceptable behind the feature).
- `tokio` 1 (transport, feature `quic`; `rt`, plus `net`/`time` via quinn): quinn's runtime. Default `osis-transport` builds have no tokio: `InProcess` runs on its own `Sched`.
- Planned, added by their plans with a line here: tokio (node, server, osis, cli, sim), arbitrary (fuzz only), iroh (feature-gated), clap (cli only), anyhow (cli, examples).

## 6. Conventions
- Every crate root: a doc comment naming its contents, layer and plan, then `#![forbid(unsafe_code)]`, and `[lints] workspace = true` in its Cargo.toml.
- Every test cites the spec section it checks (comment above it; form in notes/testing.md, Conventions), so grep and notes/testing-map.md answer "what checks §X".
- Wire choices the spec leaves open sit behind one constant or one function marked `provisional` (grep `provisional`). spec/wire.md fixes everything core holds; `format` constants are marked `fixed` with their spec section.
- Prose, comments, errors and commit messages compact; no formatting tools.

## 7. osis-core public surface
- `Value`: `Int(i64)`, `Float(Float)`, `Bool`, `Str(String)`, `Bytes(Vec<u8>)`, `Tid(Tid)`, `Enum(u64, Option<Box<Value>>)`, `Map(BTreeMap<Value, Value>)` (also structs: int keys), `List(Vec<Value>)`, `Set(BTreeSet<Value>)`, `Link(Link)`, `Unknown(Unknown)`. `Ord` is computed structurally and equals bytewise order of canonical encodings (proptest-checked), so `BTreeMap`/`BTreeSet` hold canonical order and uniqueness by construction. `Value::float(f64)`, `depth()` (arrays, maps and tags on the deepest path; a scalar is 0). Enum case IDs are u64 (CBOR uint).
- `Float`: bit pattern; `new` normalizes NaN, `from_bits` rejects other NaNs. `Unknown::new(tag, CanonicalBytes)` refuses tags this build knows (`is_known_tag`); the reserved STRUCT tag counts as unknown.
- `cbor`: `encode(&Value) -> Vec<u8>`, `encode_into`, `decode(&[u8], &Limits)` (whole input; `Limits.max_depth` counts as `depth()`), `decode_prefix` (returns the value and the bytes it spans), `Limits { max_depth, max_bytes }` (`Limits::DEFAULT` from `format`), `DecodeError` (always BadInput; one variant per rule), `CanonicalBytes` (bytes proven canonical: `parse`, `from_value`, `as_bytes`, `to_value`, `depth`). Recursive with a depth cap; claimed lengths are checked against remaining input before allocating.
- Ids: `Tid` (15 bytes; `from_bytes`, `as_bytes`, `of_record`, `Display`/`parse`/`FromStr` 20-char base64url, `to_uri` with `osis://`), `CreationRecord::{Thing{owner, nonce}, KeyActor{alg, public_key, nonce}}` with `to_value`/`from_value`/`tid` (spec/wire.md §3; `from_value` accepts only `alg` = `SIGNING_KEY_ED25519` (1) with a 32-byte key, other cases can be built but read as `None`), `Ak` (`new` validates against `format::MAX_AK_BYTES`, `is_core`, `namespace`), `Link { hash, blob, suite, key }` (`Debug` hides the key), `BlobId`/`CommitId` (32 bytes), `LabelId`/`SchemaId` (16 bytes) as public-field newtypes, `Role` (Read < Write < Admin).
- Time: `WallMs(u64)`, `Ts` (`make(wall, logical)`, `from_u64`, `to_u64`, `wall_ms`, `logical`), `Clock` (`now_wall_ms`; `Send + Sync`), `ManualClock` (`set`, `advance`), `SystemClock` (drivers only).
- `format` (spec/wire.md §2, §13, all fixed): `FORMAT_VERSION`, `TAG_*` (1616..1619, 258), `MAX_BLOB`, `CHUNK_THRESHOLD`, `PAGE_TARGET`, `CHUNK_MIN/MAX`, `CHUNK_MASK_BITS`, `TREE_FANOUT`, `TREE_MAX_LEVEL`, `BLOB_FRAMING_VERSION`, `MAX_COMMITMENTS`, `MAX_CLAIMS`, `*_MS` durations, `RESOLUTION_HOPS`, `CORE_SCHEMA_ID`/`CORE_SCHEMA_REVISION`, `MAX_VALUE_DEPTH` (64), `MAX_OBJECT_DEPTH` (512), `MAX_VALUE_BYTES`, `MAX_AK_BYTES`, `MAX_URL_BYTES`, `TID_LEN`; `MAX_MESSAGE` (protocol v1) and `TOMBSTONE_LIFETIME_MS` (policy) are not format constants.
- `chunker` (spec/wire.md §6): `GEAR` (lazy, BLAKE3 XOF), `ChunkParams { min, max, mask_bits }` (`FORMAT`; small params for tests), `Chunker::new`, `next_boundary(&[u8]) -> Option<usize>` (incremental, resets itself after a cut), `pending`, `reset`, `chunk_lengths` (one-shot); `PageCutter` for pages: `feed(bytes)` per element piece, `end_element() -> bool` (close the page after this element; resets itself), `pending`.
- `hash`: `hash`, `keyed_hash`, `derive_key`, incremental `Hasher` (keyed, XOF). `kdf` and every purpose string live in osis-crypto.
- Errors: `ErrorClass::{BadInput, Parked, Local}`, trait `Classified { fn class(&self) -> ErrorClass }`, `impl_error!(Enum { Variant => ("fmt", args), .. })` or `impl_error!(Struct, "msg")`.
- Integration test files start with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]`: clippy.toml's test exemptions cover only `#[test]` functions and `#[cfg(test)]` modules.

## 8. osis-schema public surface
- Types (spec/data-model.md §3): `Type` (mirrors §10 `type_expr`: scalars, `Text`, `List`/`Set`/`Map`, `Struct(StructType)`, `Enum(EnumType)`, `Counter`/`Max`/`Min`, `Named(name, args)` incl. `option`/`markdown`/`timestamp`/`duration`, `Param`), `Field`, `Case`.
- `Schema { id, revision, types, aspects: BTreeMap<AK, AspectDef>, signals, doc }`; `AspectDef { ty, retention: Retention, expires, flags: BTreeSet<Flag>, succeeds, doc }`; `Retention { by: PurgeBy, at_least: Bound, at_most: Bound }` (`Default` = untyped: author, no bounds), `Bound { abs, rel }` (ms), `AspectDefaults { retention, expires }`. Methods: `expand` (named types to a structure), `encoding(&Type) -> Option<Encoding>` (`None` = any), `default_of(&Field)` (declared, or `none` for option), `defaults(ak)`, `view(ak) -> SchemaView`, `validate`, `to_value`/`from_value`/`canonical_bytes`/`hash`.
- `parse(file, src) -> Result<Schema, ParseError>` (file:line:col). `core_schema()`, `core_static()`, `meta_schema()`; `StaticSchema` (embedded source, parsed once).
- Evolution: `check(old, new) -> Vec<Violation { rule: Rule, at }>`, `Lock` (`of`, `to_text`, `parse`), `check_lock(file, lock, allow) -> LockStatus`.
- Typed access (spec/versioning.md §5): `typed_read(schema, v, ty) -> Result<Value, PathError>` (projection: known fields, defaults filled; links pass for large values), `read_path`, `type_at`, `value_at`, `validate_write` (every declared field, nothing undeclared, depth). `Path(Vec<Step>)`, `Step::{Field, Case, Key, Index, Elem}`, `FieldId`, `CaseId`, `p![..]`; `PathError { path, kind: PathErrorKind }` (UnknownCase/UnknownTag parked, Schema local, rest BadInput).
- Diff: `SchemaView` implements `osis_crdt::View` (project = typed read at the position, `None` = opaque). `large_positions(schema, v, ty) -> Vec<Large { path, map_key }>`: atomic positions above `CHUNK_THRESHOLD`.
- Keys: `trait AspectKey { type T; ak, schema, decode, encode; ty, schema_ref, defaults, validate }` for `Ak` (untyped, `T = Value`) and `Aspect<T>` (const, `Aspect::new(ak, &STATIC_SCHEMA)`); `Signal<T>`. `Codec` (to/from `Value`; std impls incl. `Option` = option enum, `Vec<u8>` = blob, `[u8; N]` fixed blobs, ids, `Role`, `Ts`, `WallMs`), `codec_struct!`, `Chunked<T>`.
- `core_types`: Rust types of every core aspect (`Edge`, `Keys`, `Keyset`, `Epoch`, `Secrets`, `SecretBox`, `Tenures`, `Label`, `NodeInfo`, `Reach`, `Seen`, `Group`, agility enums, `CreationRecord` codec), constants `TID`..`GROUPS`, `MEMBERSHIP_CLASS`, `is_membership_class`.
- Codegen: `generate(schema, file, src) -> Generated { code, warnings }`, `generate_file(path)` (checks the lock; for build.rs), bin `osis-schema-gen`. `transition`: `pick_form`, `default_policy`.
