# Test infrastructure: vectors, fuzzing, CI, budgets, spec-to-test map
> Summary: Build the shared testing infrastructure of plans/testing.md §2, §4, §6 (policy part), §7, §9: the `vectors/` conformance format and runner with the freeze policy, cargo-fuzz targets per parser with committed corpora, CI (per-commit fast tier, nightly slow tier), cargo-deny and unsafe policy, size-budget and bench harnesses, coverage (measured, not gated), and the generated spec-to-test map in notes/testing.md.
> Tags: tests

Crates/dirs: `vectors/` (`osis-vectors`), `fuzz/`, `.github/workflows/`, `deny.toml`, bench harness crate `osis-bench` (optional; criterion benches may live per crate). Depends on: workspace; grows as crates land. Unblocks: hardening-signoff.
Reference: plans/testing.md (strategy; this plan executes its infrastructure items), notes/architecture.md §4 (tiers, targeted runs). Spec trumps this plan.

## Deliverables
- Vectors: directory layout per subject (`cbor/`, `tid/`, `kdf/`, `box/`, `wrap/`, `commit/`, `blob/`, `delta/`, `snapshot/`, `step/`, `inbox/`, `signal/`, `bundle/`, `proto/`), each vector = input (hex or CBOR diagnostic), expected bytes or expected decode, or expected rejection with the rule; a runner crate with one test per file; a generator binary that writes vectors from the implementation; **freeze policy**: a vector marked frozen fails the build if changed without bumping a `FORMAT_CHANGE` note (reviewed by the toplevel). Vectors stay provisional until plans/protocol-spec.md is merged, then frozen.
- Fuzz: cargo-fuzz targets for every parser of peer bytes (CBOR value, blob prefix, commit header, delta, snapshot page, proto frame and each message, bundle, inbox blob, step, link and card formats, schema DSL), `arbitrary`-based structured targets for join (random states → laws), corpora seeded from vectors and committed; a `fuzz/README` on running; crashes become regression tests in the owning crate.
- CI: `ci.yml` per commit: build, clippy `-D warnings`, `cargo deny`, tier-1 tests (`cargo test --workspace` with `PROPTEST_CASES=32`), vectors; `nightly.yml`: tier-2 (`--ignored`, `OSIS_SLOW=1`), fuzz for a time budget per target, `sim-sweep`, large model instances, TLC smallest instances (plans/tla-models.md); artifacts for failing seeds. Caching for fast builds; the workspace split keeps per-crate jobs possible later.
- Policy checks: `#![forbid(unsafe_code)]` grep check, `cargo deny` (licences, duplicate versions, advisories), dependency allowlist check against notes/architecture.md (a small script).
- Size budgets as tier-2 tests with a margin (from notes/crdt.md and notes/crypto.md numbers): minimal commit, removal from an N-member roster, roster snapshot of N, revoke frontier after a long tenure, text of M chars after K edits; benches with criterion tracked, not gated.
- Coverage job (llvm-cov) reporting untested decoder branches.
- Spec-to-test map: a script that greps test names and comments for `§` citations per spec file and writes the table into notes/testing.md with gaps listed; gaps are treated like issues in hardening-signoff.

## Steps
- [ ] Vectors format + runner + first vectors (CBOR, tid, kdf) with core/crypto; freeze mechanism.
- [ ] Fuzz skeleton with the first targets (CBOR, chunker); add a target as each parser lands (owning plans call this out).
- [ ] CI per-commit and nightly workflows; deny; policy scripts.
- [ ] Budgets and bench harness; coverage; spec-to-test map script, first table in notes/testing.md.

## Done when
CI runs both tiers; every parser has a fuzz target with a corpus; the spec-to-test map is generated; notes/testing.md exists describing how to run everything. Then plans/testing.md and this plan are deleted (content into notes/testing.md).

## Progress
