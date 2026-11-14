# Testing
> Summary: Index of the testing notes, plus what every test follows: principles, what finds bugs, when each kind of test runs (gate, release checks, by hand) and what a worker runs, sizes, conventions every crate follows, the default-test cost, and what nothing covers.

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
| build and gate costs, time limits | notes/build.md, What things should cost and Time limits |
| what a good test is, open test-system work | notes/test-design.md |

## Principles
- The spec is the oracle: every MUST has a test that fails without it, and every test cites the spec section it checks, so `grep` (or notes/testing-map.md: notes/gate.md, Spec-to-test map) answers "what checks §X".
- Determinism: seeded randomness, injected clocks, in-process transport. A failure is a seed; a flake is a bug. The default tests never sleep, assert on wall time or touch the network.
- Peer bytes never panic: every parser is fuzzed; decoders take limits.
- Models are independent oracles: the implementation never depends on them and they are never patched to match it.
- Design rules for tests (one property test per property, oracles compare what users observe, never pin a seed): notes/test-design.md and notes/coordination.md, Design principles.

## What finds bugs
Over about 200 merged tasks: reading in review, audits and simplification passes found about 180 product bugs; a new targeted test or differential for the branch about 45; per-branch properties at small size about 25; larger ranges, release checks and wide sweeps 15-19; dogfooding about 10; the default tests 2; TLA one (a model extended in review by the action the code met and the model lacked: a re-grant, data loss); re-running already-run ranges about 4 (all regressions). Of about 38 classified seed-found bugs, about 14 were slips against a clear rule and about 24 had no rule yet (the fix wrote a new spec sentence, a stated limit or a redesign); they clustered (arrival order × retention × validity, epochs and rotation, ephemeral), and each chase ended with a study that found one root shape, never with more seeds. Hence (notes/coordination.md, Test budget): per-branch sizes a tenth of large, breadth only in release checks, never rerun old ranges, one all-core run at a time per box, a study after the second seed fix in an area, and time spent on reviews that read, audits, dogfooding and targeted differentials.

The sync rewrite's 14 module reviews (about 50 product bugs, Phase 3 of issues/sync-rewrite.md) split the same way: reading against the spec and asking what a hostile peer or removed party controls found most, in four shapes: state a peer or time grows without bound (about 12), authority or information from unproven input (about 7), clock, restart and ordering (about 6), plain spec mismatch (about 10); seams between modules (wrong key passed in, cursors of two logs mixed) the rest. A random-history differential found 2, routing scripted peers through the real decoder 2, a max-RSS probe 1 (a decoder's embedded items uncounted), paper walks of two flows 2 shape bugs before code. Mutation found no product bug but about 8 tests passing with their rule removed (a lazily built index refusing first, an empty log skipping the path, a fake consuming the count its assert read). These are the module worker's up-front checks (notes/coordination.md, Briefs).

## When tests run
Everything runs locally; there is no CI. Tests are organised by when they run, not by kind.

| when | what | how |
|---|---|---|
| the gate, once per branch | the default tests (every test not `#[ignore]`: unit, small proptest, vectors, scale counts) plus the properties and sim scenarios the branch's changes reach, at small size | `tools/gate.sh` (notes/gate.md) |
| release checks | the same properties and scenarios at large size on fresh seeds; when Tess asks and in the release process | notes/coordination.md, Release checks |
| by hand | fuzz, TLA+, roles-model searches, benches and memory checks, coverage, real-network tests, `#[ignore]` tests without a size word | By hand, below, by a branch that touches the area |

**A worker** runs the default tests of each crate it touched (`cargo test -p <crate>`), plus `cargo test -p osis --test it` when it changed engine judgment (validity, keys, rotation, ending: the osis crate holds the cross-crate flows, and reviews failed on it after workers ran only the engine's), `-p osis-sync` when it changed the engine's sync facade, and `-p held-model` when it changed crdt-model; clippy; and the instant checks (`python3 tools/policy.py`, `python3 tools/spec_map.py --uncited --gaps`). The gate is the branch's one full run (notes/coordination.md, Test budget).

**Sizes**: a property's documented range or sample count is its large size (`OSIS_FULL=1`, release checks only); its small size, the gate's, is a tenth (`osis_base::testenv::large`, at least one seed); explicit `OSIS_*_START`/`_SEEDS` override both. Sim scenarios: 15 seeds small, 150 large. A property taking over 5 minutes alone at small size on a quiet box gets an issue to make it shorter. Scale is checked by counting work in the default tests, never by timing (notes/test-scale.md).

**By hand**, alone under `tools/heavy` when it uses every core:
- TLA+ when a model or its spec sections change: `core/test/tla/run.sh <module>` (notes/test-properties.md, Models).
- Networking, for a sync, link or transport change: the networking command (notes/build.md, Profile and command forms; real sockets, not seeded, so any failure is a bug).
- Slow or special `#[ignore]` tests, by name (`cargo test -p <crate> --test it -- --ignored <name>`): osis-crdt `stream_memory_big_map` (alone, `--exact`).
- Fuzz (notes/test-properties.md, Fuzzing); roles-model searches (notes/test-properties.md, Models); sim seeds beyond the gate's (`sim-sweep`, notes/test-sim.md); `cargo bench` and memory checks (notes/test-scale.md); coverage: `cargo llvm-cov --lcov --output-path lcov.info` if installed (measured, never gated; read it for untested decoder branches).

## Conventions
- **One test binary per crate**: `tests/it/main.rs` with a module per file, so a test's name is `<module>::<fn>`. Single-file crates (osis-base, osis-vectors, crdt-model) keep `tests/<file>.rs` (`--test cbor`, `--test vectors`, `--test props`). Nothing requires nextest, nightly or cargo-fuzz.
- **Spec citations**: `// spec/<file>.md §N[.M]: <what>` right above each `#[test]` (inside `proptest!` too); a bare `§N` refers to the last file named in that comment; a test without its own inherits the file's `//!` header citations; infrastructure tests say `// spec: none (<why>)`. `tools/spec_map.py --uncited` enforces it. An anchor `§N (name)` names the rule: each `;`-separated name (a `: gloss` after it is free) must be text of §N or a RULES anchor there, else `--gaps` fails; put commentary after the parenthesis, never in it.
- **Ignored tests**: a property is named with a size word (notes/gate.md, The selection); a by-hand test says why (`#[ignore = "by hand: ..."]`); a known-failing reproducer is `#[ignore = "issues/<name>.md"] repro_*`. A crate's default tests stay under about 10 s each.
- **Seeds are 0**: a test writes the behaviour it intends; a world or rng seed is 0, and a case the seed happened to reach is constructed (draw tids until one sorts as wanted, try values until the case shows). Distinct numbers stay only where distinctness is the point: node identities, opens of one store, rotations of things whose secrets must differ, seals that must not share a nonce. The default tests replay no pinned seed: a failing seed becomes a hand-written example, a `repro_*`, or nothing.
- **Network**: sync's tests run nodes over the sync harness's fabric (notes/sync-test-harness.md); osis-transport's own tests use `osis_transport::{Net, Sched}` (in-process, virtual steps, seeded faults and scheduling; no tokio); real-socket tests (QUIC on localhost) are by hand. `peer://` in process runs the real P2P code over the nat.rs model: with no route no dial succeeds. Under tokio, `Net::run_on_tokio` runs the net with one model ms per wall ms; a test whose dials must fail sets `Net::set_dial_ms` (`0`: one packet). LAN announcements run over the model (`MemUdp::on_lan`, `Transport::lan`, `Net::set_lan_loss`); sync's discovery runs over the sync harness's reachability model instead (notes/sync-test-harness.md); negatives count announcements heard, never wait. `Net::punches` counts punch packets.
- **The real LAN**: tests run side by side on one box, so none binds port 47380 or announces on the real network (tools/policy.py enforces the shapes). A node a test builds starts from `internals::Opening` (`Lan::Off`) or uses `MemLan`; the `osis` binary under test runs with `--no-lan`; a real-socket LAN test takes an OS-picked free port and loopback targets. The one exception is `announce_v6_every_interface_spec_sync_10` (by hand, through `tools/heavy`).
- **Vectors, fuzz targets, budgets**: notes/test-properties.md (Conformance vectors, Fuzzing), notes/test-scale.md.

## Default-test cost
Compare by instruction counts: a test's count repeats to under 0.1% run to run, its CPU-s by 20-40% and its wall more (load, SMT, clocks). The default tests' cost is not measured on the rebuilt sync; the gate's figures are notes/time-limits.md.
- Measured not to help: every binary at once, harness inner threads at 1, opt-level 2 for the workspace crates (one-line edit builds 15-20% slower), selecting default-test crates by the diff (engine takes most commits: 15% at best, opens a gap). Only less work shortens it.
- In place: osis-crypto at `opt-level = 2` in dev; smaller data where the property is relative; properties for sizes; one setup copied per order where a test plays many orders from one start (`local_peer::Peer::fork`), and cases sharing a setup copy it (`LocalPeer::cached`); tests looping over fixed seeds or cases run them on the seed runner (`stream::stream_differential_*`); memo hits compared with a fresh run in debug builds (`osis_base::memo` `Checks`); decoded commit records and parts (`engine/decoded.rs`) checked at every hit by comparing the bytes each was decoded from with those read now, never decoded again (decoding is a pure function of those bytes, so a stale or misfiled entry shows as differing bytes); engine reads (`Engine::read`: a store transaction dropped after and its in-memory changes undone) do none of a transaction's end work, and a debug build asserts each changed nothing (the store, blobs, or anything `Core::rollback_to` restores); `LocalPeer::sync_all` stops after a round of duplicates (a fixpoint); the forensic attack's last-byte key test (notes/test-security.md).
- Per test, every test: `tools/pertest.py run OUT` builds the default tests, copies their binaries aside, then (under `tools/heavy`, taken after the build, so editing while it waits changes nothing measured) runs each listed default test as its own process `--exact <name> --test-threads=1` from its package dir under `tools/icount`, writing name, instructions, CPU-s and exit code per line. `tools/pertest.py top OUT` lists per-binary totals and the costliest tests; `compare OLD NEW` the moves by test (crdt-model's and osis-keys' proptests draw fresh seeds per run and move 7-8% between identical runs: noise; a test failing only at pertest's load may be a KNOWN flake, tools/known_failures.txt). A compare against the last profile is also a cheap check for a storm that landed passing (a test 20x its old count). Against an older revision: `run` in a second worktree (`wt claim <name> <rev>`), `compare` here. Each test is its own process, so a cached setup is built by every test using it: its saving shows only over a whole binary or module in one process (`tools/icount BIN -q <module>::`). The `test` limit alone (10 CPU-s or 15 s wall): `tools/limits.py tests`.
- Per-test times: run a test binary with `RUSTC_BOOTSTRAP=1 <binary> -Z unstable-options --report-time` from its package dir; CPU per test with `/usr/bin/time <binary> --exact <name>`. Where a test's CPU goes: `tools/cpuprof` (notes/test-harnesses.md, Measuring). A test binary run outside cargo runs proptests at 256 cases: set `PROPTEST_CASES=32 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` as `.cargo/config.toml` does.

## Not covered
The scale properties with no counter (notes/test-scale.md), the TLA+ "not covered" list (notes/test-properties.md, Models), QUIC and P2P over real sockets outside the by-hand networking check, browsers, real networks beyond localhost, GUI smoke tests of the app, and a 10^4-seed sim sweep per scenario (about 6 h on a quiet 16-core box).
