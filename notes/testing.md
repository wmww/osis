# Testing
> Summary: Index of the testing notes, plus what every test follows: principles, when each kind of test runs (gate, release checks, by hand) and what a worker runs, sizes, conventions every crate follows, and what nothing covers.

## Where to look
| question | where |
|---|---|
| the command for the default tests, one crate, clippy, a property, sim-sweep, old vs new | notes/build.md, Profile and command forms |
| what a worker runs before finishing | When tests run, below |
| what the gate runs, its per-branch selection, KNOWN and NEW failures, policy and spec-map checks | notes/gate.md |
| replay a failing seed, harness env vars, seed runners, the property list | notes/test-harnesses.md, Env vars and seeds |
| cached setups and world copies; the debug rebuild and index checks | notes/test-harnesses.md |
| count instructions, profile, compare against main | notes/test-harnesses.md, Measuring |
| footguns | notes/build.md, Footguns; notes/test-harnesses.md, Harness footguns |
| held-set and rotation properties, crdt/roles/held models, TLA+, vectors, fuzz | notes/test-properties.md |
| the simulator, its scenarios and sweeps | notes/test-sim.md |
| scale checks, budgets, benches, memory checks, performance targets | notes/test-scale.md |
| forensic attack, metadata and negative tests, security reviews | notes/test-security.md |
| build costs; gate stage costs and time limits | notes/build.md, What things should cost; notes/time-limits.md |
| what a good test is, what finds bugs, open test-system work | notes/test-design.md |
| the default-test cost, per-test profiles | notes/test-harnesses.md, Default-test cost |

## Principles
- The spec is the oracle: every MUST has a test that fails without it, and every test cites the spec section it checks, so `grep` (or notes/testing-map.md: notes/gate.md, Spec-to-test map) answers "what checks §X".
- Determinism: seeded randomness, injected clocks, in-process transport. A failure is a seed; a flake is a bug. The default tests never sleep, assert on wall time or touch the network.
- Peer bytes never panic: every parser is fuzzed; decoders take limits.
- Models are independent oracles: the implementation never depends on them and they are never patched to match it.
- Design rules for tests (one property test per property, oracles compare what users observe, never pin a seed): notes/test-design.md and notes/principles.md.

## When tests run
Everything runs locally; there is no CI. Tests are organised by when they run, not by kind.

| when | what | how |
|---|---|---|
| the gate, once per branch | the default tests (every test not `#[ignore]`: unit, small proptest, vectors, scale counts) plus the properties and sim scenarios the branch's changes reach, at small size | `tools/gate.sh` (notes/gate.md) |
| release checks | the same properties and scenarios at large size on fresh seeds; when Tess asks and in the release process | notes/coordination.md, Release checks |
| by hand | fuzz, TLA+, roles-model searches, benches and memory checks, coverage, real-network tests, `#[ignore]` tests without a size word | By hand, below, by a branch that touches the area |

**A worker** runs the default tests of each crate it touched (`cargo test -p <crate>`), plus `cargo test -p osis --test it` when it changed engine judgment (validity, keys, rotation, ending) or what syncs or is kept (the sync set, closures, forgetting): the osis crate holds the cross-crate flows, and reviews failed on it after workers ran only the engine's and sync's, `-p osis-sync` when it changed the engine's sync facade, `-p held-model` when it changed crdt-model, and `-p osis-cli -p osis-chat` when it changed schema/ (the CLI tests write core values as text: a new field broke them on main unseen); clippy; and the instant checks (`python3 tools/policy.py`, or `--baseline` while main is red, `python3 tools/spec_map.py --uncited --gaps`), spec_map right after writing a cited test, not after the test run: an anchor must be words of the section or a RULES anchor, each `;`-separated piece alike, and its stray message quotes the whole parenthesis without naming the failing piece. The gate is the branch's one full run (notes/coordination.md, Test budget).

**Sizes**: a property's documented range or sample count is its large size (`OSIS_FULL=1`, release checks only); its small size, the gate's, is a tenth (`osis_base::testenv::large`, at least one seed); explicit `OSIS_*_START`/`_SEEDS` override both. Sim scenarios: 15 seeds small, 150 large. A property taking over 5 minutes alone at small size on a quiet box gets an issue to make it shorter. Scale is checked by counting work in the default tests, never by timing (notes/test-scale.md).

**By hand**, alone under `tools/heavy` when it uses every core:
- TLA+ when a model or its spec sections change: `core/test/tla/run.sh <module>` (notes/test-properties.md, Models).
- Networking, for a sync, link or transport change: the networking command (notes/build.md, Profile and command forms; real sockets, not seeded, so any failure is a bug).
- Slow or special `#[ignore]` tests, by name (`cargo test -p <crate> --test it -- --ignored <name>`): osis-crdt `stream_memory_big_map` (alone, `--exact`).
- The custody differential, when the custody code changes (engine `flows/custody.rs`, `flows/account.rs`, `sides.rs`, roles-model `custody`): `tools/heavy cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_by_hand_spec_permissions_5_4` (200 worlds, about 650 CPU-s). Not gated: notes/redesign-plan.md A4 deletes its machinery, and its failures wait in issues/custody-differential-failures.md.
- Fuzz (notes/test-properties.md, Fuzzing); roles-model searches (notes/test-properties.md, Models; `-- 0 custody-exh` when `custody.rs` changes: the gate runs only random custody worlds); sim seeds beyond the gate's (`sim-sweep`, notes/test-sim.md); `cargo bench` and memory checks (notes/test-scale.md); coverage: `cargo llvm-cov --lcov --output-path lcov.info` if installed (measured, never gated; read it for untested decoder branches).

## Conventions
- **One test binary per crate**: `tests/it/main.rs` with a module per file, so a test's name is `<module>::<fn>`. Single-file crates (osis-base, osis-vectors, crdt-model) keep `tests/<file>.rs` (`--test cbor`, `--test vectors`, `--test props`). Nothing requires nextest, nightly or cargo-fuzz.
- **Spec citations**: `// spec/<file>.md §N[.M]: <what>` right above each `#[test]` (inside `proptest!` too); a bare `§N` refers to the last file named in that comment; a test without its own inherits the file's `//!` header citations; infrastructure tests say `// spec: none (<why>)`. `tools/spec_map.py --uncited` enforces it. An anchor `§N (name)` names the rule: each `;`-separated name (a `: gloss` after it is free) must be text of §N or a RULES anchor there, else `--gaps` fails: a phrase copied from the section's body, not a descriptive name (`(link peers)`, `(Delete by levels)` for a section named `Delete` failed), on one comment line (a reflowed break leaves two spaces inside it); put commentary after the parenthesis, never in it.
- **Ignored tests**: a property is named with a size word (notes/gate.md, The selection); a by-hand test says why (`#[ignore = "by hand: ..."]`); a known-failing reproducer is `#[ignore = "issues/<name>.md"] repro_*`. A crate's default tests stay under about 10 s each.
- **Seeds are 0**: a test writes the behaviour it intends; a world or rng seed is 0, and a case the seed happened to reach is constructed (draw tids until one sorts as wanted, try values until the case shows). Distinct numbers stay only where distinctness is the point: node identities, opens of one store, rotations of things whose secrets must differ, seals that must not share a nonce. No test replays a pinned seed or a shrunk random script: a bug a random test finds becomes a new hand-written test holding only what triggers it (notes/principles.md, Never pin a seed), an ignored hand-written `repro_*` while its issue is open, or nothing. tools/policy.py `pinned_seeds` refuses a nonzero literal seed given to sync's harness worlds and histories (`world`, `history`, `World::new`).
- **Network**: sync's tests run nodes over the sync harness's fabric (notes/sync-test-harness.md); osis-transport's own tests use `osis_transport::{Net, Sched}` (in-process, model time, seeded scheduling; no tokio); real-socket tests (QUIC on localhost) are by hand, but for two default ones in osis's `runtime` module that run what only the real runtime runs: `osis serve`'s listeners on one host (it binds `peer://`'s fixed port when free) and two accounts syncing over loopback QUIC. `peer://` in process runs the real P2P code over the nat.rs model: with no route no dial succeeds. LAN announcements run over the model (`MemUdp::on_lan`, `Transport::lan`); sync's discovery runs over the sync harness's reachability model instead (notes/sync-test-harness.md); negatives count announcements heard, never wait. `Net::punches` counts punch packets.
- **The real LAN**: tests run side by side on one box, so none binds port 47380 or announces on the real network (tools/policy.py enforces the shapes). A node a test builds starts from `internals::Opening` (`Lan::Off`) or uses `MemLan`; the `osis` binary under test runs with `--no-lan`; a real-socket LAN test takes an OS-picked free port and loopback targets. The one exception is `announce_v6_every_interface_spec_sync_10` (by hand, through `tools/heavy`).
- **Vectors, fuzz targets, budgets**: notes/test-properties.md (Conformance vectors, Fuzzing), notes/test-scale.md.

## Not covered
The scale properties with no counter (notes/test-scale.md), the TLA+ "not covered" list (notes/test-properties.md, Models), QUIC and P2P over real sockets outside the by-hand networking check, browsers, real networks beyond localhost, GUI smoke tests of the app, and a 10^4-seed sim sweep per scenario (about 6 h on a quiet 16-core box).
