# Test infrastructure: vectors, fuzzing, CI, budgets, spec-to-test map
> Summary: Build the shared testing infrastructure of plans/testing.md §2, §4, §6 (policy part), §7, §9: the `vectors/` conformance format and runner with the freeze policy, cargo-fuzz targets per parser with committed corpora, CI (per-commit fast tier, nightly slow tier), cargo-deny and unsafe policy, size-budget and bench harnesses, coverage (measured, not gated), and the generated spec-to-test map in notes/testing.md.
> Tags: tests

Crates/dirs: `vectors/` (`osis-vectors`), `fuzz/`, `.github/workflows/`, `deny.toml`, bench harness crate `osis-bench` (optional; criterion benches may live per crate). Depends on: workspace; grows as crates land. Unblocks: hardening-signoff.
Reference: plans/testing.md (strategy; this plan executes its infrastructure items), notes/architecture.md §4 (tiers, targeted runs). Spec trumps this plan.

## Deliverables
- Vectors: directory layout per subject (`cbor/`, `tid/`, `kdf/`, `box/`, `wrap/`, `commit/`, `blob/`, `delta/`, `snapshot/`, `step/`, `inbox/`, `signal/`, `bundle/`, `proto/`), each vector = input (hex or CBOR diagnostic), expected bytes or expected decode, or expected rejection with the rule; a runner crate with one test per file; a generator binary that writes vectors from the implementation; **freeze policy**: a vector marked frozen fails the build if changed without bumping a `FORMAT_CHANGE` note (reviewed by the toplevel). Vectors stay provisional until plans/protocol-spec.md is merged, then frozen.
- Fuzz: cargo-fuzz targets for every parser of peer bytes (CBOR value, blob prefix, commit header, delta, page, proto frame and each message, bundle, inbox blob, step, link and card formats, schema DSL), `arbitrary`-based structured targets for join (random states → laws), corpora seeded from vectors and committed; a `fuzz/README` on running; crashes become regression tests in the owning crate.
- CI: `ci.yml` per commit: build, clippy `-D warnings`, `cargo deny`, tier-1 tests (`cargo test --workspace` with `PROPTEST_CASES=32`), vectors; `nightly.yml`: tier-2 (`--ignored`, `OSIS_SLOW=1`), fuzz for a time budget per target, `sim-sweep`, large model instances, TLC smallest instances (plans/tla-models.md); artifacts for failing seeds. Caching for fast builds; the workspace split keeps per-crate jobs possible later.
- Policy checks: `#![forbid(unsafe_code)]` grep check, `cargo deny` (licences, duplicate versions, advisories), dependency allowlist check against notes/architecture.md (a small script).
- Size budgets as tier-2 tests with a margin (from notes/crdt.md and notes/crypto.md numbers): minimal commit, removal from an N-member roster, roster snapshot of N, revoke frontier after a long tenure, text of M chars after K edits; benches with criterion tracked, not gated.
- Coverage job (llvm-cov) reporting untested decoder branches.
- Spec-to-test map: a script that greps test names and comments for `§` citations per spec file and writes the table into notes/testing.md with gaps listed; gaps are treated like issues in hardening-signoff.

## Vectors required (from protocol-spec)
Generate each from the crates with the fixed inputs given (seeds are 32 repeated bytes unless stated; randomness injected through a test hook); spec/wire.md is the layout reference. Everything listed is frozen once reviewed.
- `cbor/` (hand-written, trivially checkable): `0` → `00`; `23` → `17`; `24` → `1818`; `-1` → `20`; i64 max → `1b7fffffffffffffff`; i64 min → `3b7fffffffffffffff`; `1.0` → `fb3ff0000000000000`; `-0.0` → `fb8000000000000000`; NaN → `fb7ff8000000000000`; true/false → `f5`/`f4`; `"a"` → `6161`; `h'01'` → `4101`; `{1: 2, 0: 3}` → `a200030102`; `set{2, 1}` → `d90102820102`; tid of 15 zero bytes → `d906504f` + 15 × `00`; `option` none → `d906518100`, some(5) → `d90651820105`. Rejections: `f93c00` (short float), `f6` (null), `1800` (non-shortest), `9fff` (indefinite), `a201020003` (unsorted map), duplicate keys, `1b8000000000000000` (above i64), NaN with payload, value nested 65 deep.
- `padme/` (hand-written): `L = len(P) + 1` → `padme(L)`: 1→1, 2→2, 4→4, 8→8, 9→10, 15→16, 17→18, 100→104, 255→256, 257→272, 1000→1024, 4097→4352, 65537→67584, 131073→135168, 1000000→1015808; unpad rejections: no `0x80`, nonzero after the marker, padded length not `padme`.
- `tid/`: ordinary record (owner 15 × `01`, nonce 32 × `02`) and key-actor record (signing key from seed `03`; nonce random 32 × `04`, and seed-derived for a link key) → canonical bytes, tid, text form; rejection: both fields 0 and 1.
- `kdf/`: every purpose string in spec/ (thing/role/label/claim/box/history/wrap/delete token/delta/link/link tree/lan tag/creation nonce/sign/kem, plus `derive_key("osis v1 dedup")`) with secret `11`, fixed input.
- `keys/`: from seed `05`: Ed25519, X25519 and ML-KEM-768 public keys, claim key (DH with a second seed `06`, fixed label ID and step key), static entry, label role keys at index 0 and 1.
- `box/`: hybrid sealed box (fixed ephemeral seeds), `/secrets` box in both forms with AD, history box, entry box; tamper and wrong-AD rejections.
- `wrap/`: a wrap for a fixed blob ID, read secret and blob key.
- `blob/`: prefixes with 0, 1, 3, 16 commitments, with and without expiry; a full commit blob, chunk blob and page blob from fixed keys and salts with blob IDs; rejections (17 commitments, unsorted, level 0 or 4, bad padding).
- `chunker/`: hash of the 2048-byte gear table plus `G[0]`, `G[255]`; boundaries of 4 MiB of BLAKE3 XOF output of `"osis test chunker"` and of 1 MiB of zeros (forced `CHUNK_MAX`); chunk tree of a 64 MiB XOF value: levels, node sizes, root content hash (dedup secret `07`); page split of a fixed element list; link-page grouping.
- `commit/`: one header per kind (0..5) with fixed fields, an aspect list just below and just above `CHUNK_THRESHOLD` (inline vs link), a purge item of each form, a demotion frontier → canonical bytes, commit ID, signature (node seed `08`); rejections from spec/commits.md §2.
- `step/`: genesis and child step (admin secret `09`), claim set with two DH readers, one static entry with its entry box and fixed padding keys → bytes, claims hash, step IDs, label ID.
- `inbox/`, `signal/`: one inbox blob and one signal envelope with publish authorization from fixed seeds.
- `link/`, `card/`: canonical bytes and text forms, with and without peers; cap rejections.
- `schema/`: the core schema (spec/data-model.md §9) as a `schema` value: canonical bytes.
- `proto/`: Hello and one message of every kind; frame header; fingerprint of a fixed set; a full reconciliation transcript between two 10 000-ID sets (IDs from BLAKE3 XOF, 100 differences each way) with the reference split rule (subrange bounds = the first own ID of each subrange); a cursor sync and a push.
- `bundle/`: a bundle with one label path, two blobs (one under two labels), entries, a deletion and a timed deletion.

## Steps
- [ ] Vectors format + runner + first vectors (CBOR, tid, kdf) with core/crypto; freeze mechanism.
- [ ] Fuzz skeleton with the first targets (CBOR, chunker); add a target as each parser lands (owning plans call this out).
- [ ] CI per-commit and nightly workflows; deny; policy scripts.
- [ ] Budgets and bench harness; coverage; spec-to-test map script, first table in notes/testing.md.

## Done when
CI runs both tiers; every parser has a fuzz target with a corpus; the spec-to-test map is generated; notes/testing.md exists describing how to run everything. Then plans/testing.md and this plan are deleted (content into notes/testing.md).

## Progress
