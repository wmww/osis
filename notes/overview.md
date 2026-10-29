# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
The repo is meant to become a small monorepo of projects worked on independently (owner): core (with cli and schema), and later kit (UI toolkit) and app (notes/app.md), each with its own checks.
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. Until a stable release, spec edits need no owner sign-off; changes to or conflicts with spec/requirements.md go to the owner.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and pending owner decisions (`grep -l owner-call issues/*`); each has Summary, Tags and a Repro line. Tags: `security`, `performance`, `tests`, `post-mvp`, `owner-call`, component names. `plans/`: work not done yet; the MVP plans are all done or turned into issues. notes/mvp-progress.md holds the MVP final report.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
The MVP is built: every subsystem of the spec is implemented and tested (final report, deviations and open issues: notes/mvp-progress.md). Design is settled; byte layouts are in spec/wire.md; conformance vectors are all provisional until the first stable release (nothing is frozen or logged as a format change before then).

Code map (crate DAG and rules: notes/architecture.md):
- `core/` (package names keep the `osis-` prefix): `base` osis-base (values, CBOR, ids, chunker), -crypto, -crdt, -schema, -perm, -store (encrypted local store), -commit, -keys, -label (blobs, labels, steps, large values), -proto (sans-I/O sync protocol), -transport (in-process, QUIC, iroh, LAN), -server (blind node), -node (engine, sync engine, membership flows), `osis` (the app API), `bench` osis-bench. `cli/` osis-cli (binary `osis`).
- `schema/` the first-party schema files, their scenario tests in core/osis's test binary (notes/std.md); `core/test/sim/` the deterministic simulator (notes/testing.md); `core/test/vectors/` conformance vectors; `core/test/fuzz/` cargo-fuzz targets; `core/test/crdt-model` and `core/test/membership-model` reference models, `core/test/tla` TLA+ `sync`, `rotation` and `membership`; `tools/` policy.py, spec_map.py, fixpoint.

What runs where (details and latest numbers: notes/testing.md):
- Tier 1, `cargo test --workspace`: everything below the sim's long scenarios; green.
- Tier 2, `cargo test --workspace -- --ignored --skip sweep --skip scale:: --skip bench::` (those timing checks by hand in release): scale checks, budgets, long sim scenarios, the localhost CLI session; known failures each have an issue.
- Nightly: fuzzing, `sim-sweep`, `core/test/tla/run.sh small`, coverage.
- Behind features, off by default: iroh P2P (`iroh`, transport and node only), LAN announcements (`lan`). Tests of those run with `cargo test-net` (tier 2). QUIC and the redb file store are always built.

How to run:
- CLI: `cargo run --bin osis -- --help`; `osis -s DIR init`, writes, `osis serve` for a local server (notes/cli.md).
- Server: `cargo run --bin osis-server -- --help` (or `osis serve`); prints `quic://host:port#key`.
- Standard data scenarios: core/osis's `contact`, `event`, `notes`, `tags` tests in `cargo test --workspace`.
- Sim: `cargo run --bin sim-sweep -- --seeds N --budget-secs T`; replay a failing seed with `osis_sim::replay("<scenario>", <seed>)`.
- Models: `core/test/tla/run.sh small` (Java); their tests run in `cargo test --workspace`; `cargo run --bin membership-model`.

Known open (issues/): owner tradeoffs stated in user terms (aspect-key-format); cost residues (perm-eval-cost, node-core-gaps, node-sequences-not-paged, crdt-seq-linearization-cost); rough edges (node-sync-gaps, link-race-edge-only-pending); api-deferred (queries are a design pass), in-memory-things; tests-unbuilt (10^4-seed sweep, model refactors).

- MVP scope (owner): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: owner and agent iterate by discussion. Notes mark what was the owner's decision, the agent's call or a proposal. Decisions waiting on the owner are issues tagged `owner-call`.

## Notes
- notes/architecture.md: crate map and DAG, fixed abstractions, error classes, build and test rules, dependency allowlist, osis-base and osis-schema surfaces, where each crate's notes live.
- notes/mvp-progress.md: the MVP final report and how to resume.
- notes/api.md: the designed API shape (sync data API, typed keys, watches, `Write` with `set`/`edit`, sharing and sync surface), fixed directions, footguns closed, rejected shapes.
- notes/data-model.md: tids, CBOR, large values, namespaces, schema DSL sketch.
- notes/versioning.md: transition conventions, write policy, blessed paths for hard schema changes.
- notes/crdt.md: merge design reasons, anomalies, reference model, text size, worked examples.
- notes/permissions.md: permission rules' reasons, membership model findings, move (copy) and revocation reasoning, sharing patterns.
- notes/sync.md: sync and blind-node reasons, limits, what a blind node learns, policy defaults.
- notes/crypto.md: suite choices, costs, crates.
- notes/ephemeral.md: ephemeral data design (in-memory things and aspects, persistence, synced envelopes with poke liveness, signals folded in, plan), expiry, the all-nodes predicate, heartbeats and the stranded flag.
- notes/chat.md: the chat pattern derived from the current design, with costs (thrown out; kept for its measured costs until the redesign, notes/std.md).
- notes/tags.md: the standard core aspects (`/name`, `/body`, `/tag`), tags as marked groups in a graph, sharing a tag per item through one nested roster, the confirmation guideline.
- notes/networking.md: transports (iroh, direct servers), official infrastructure, push wake-up proposal, risks.
- notes/local-store.md: encrypted local store and key-erasure deletion.
- notes/node.md: osis-engine and osis-node module layout, engine surface, store records, node-core readings.
- notes/cli.md: the `osis` command-line tool (command table, value syntax, JSON, exit codes).
- notes/std.md: the first-party schemas (notes, contacts, events), the time types, what was left out of vCard and iCalendar, the scenario tests.
- notes/testing.md: tiers, vectors, fuzzing, simulator, budgets, policy checks; notes/testing-map.md: the generated spec-to-test map.
- notes/app.md: the first-party app's design direction (facet views, lenses, state in osis, Masonry without Xilem, platform work, prototype order).
- notes/explainer.md: the docs site.
