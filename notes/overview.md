# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized data layer optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
The repo is meant to become a small monorepo of projects worked on independently (Tess): core (with cli and schema), `libs/` (what some but not all users of osis want: chat, the kit UI toolkit) and app (notes/app.md), each with its own checks (the gate picks them by changed paths, notes/build.md).
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. A design that cannot meet an item gets no footnote: the item is changed to say what actually holds. Until a stable release, spec edits need no Tess's sign-off; changes to or conflicts with spec/requirements.md go to Tess.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and decisions pending with Tess (`grep -l tess-call issues/*`); each has Summary, Tags and a Repro line. Tags: `security`, `performance`, `tests`, `post-mvp`, `tess-call`, component names. `plans/`: work not done yet; the MVP plans are all done or turned into issues. notes/mvp-progress.md holds the MVP final report.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
The MVP is built: every subsystem of the spec is implemented and tested (final report, deviations and open issues: notes/mvp-progress.md). Design is settled; byte layouts are in spec/wire.md; conformance vectors are all provisional until the first stable release (nothing is frozen or logged as a format change before then).

Code map (crate DAG and rules: notes/architecture.md):
- `core/` (package names keep the `osis-` prefix): `base` osis-base (values, CBOR, ids, chunker), -crypto, -crdt, -schema, -perm, -store (encrypted local store), -commit, -keys, -label (blobs, labels, steps, large values), -proto (sans-I/O sync protocol), -transport (in-process, QUIC, iroh, LAN), -host (host), -node (engine, sync engine, role flows), `osis` (the app API), `bench` osis-bench. `libs/chat` osis-chat. `cli/` osis-cli (binary `osis`).
- `libs/kit/` osis-kit (UI toolkit over Masonry) and `app/` osis-app (binary `osis-app`, prototype notes app): their own Cargo workspace rooted at libs/kit/Cargo.toml (notes/app.md).
- `schema/` the first-party schema files, their scenario tests in core/osis's test binary (notes/std.md); `core/test/sim/` the deterministic simulator (notes/testing.md); `core/test/vectors/` conformance vectors; `core/test/fuzz/` cargo-fuzz targets; `core/test/crdt-model` and `core/test/roles-model` reference models, `core/test/tla` TLA+ `sync`, `rotation` and `roles`; `tools/` policy.py, spec_map.py, fixpoint.

What runs where (details and latest numbers: notes/testing.md):
- Tier 1, `cargo test --workspace`: everything below the sim's long scenarios; green.
- Tier 2, `cargo test --workspace -- --ignored --skip sweep --skip scale:: --skip bench::` (those timing checks by hand in release): scale checks, budgets, long sim scenarios, the localhost CLI session; known failures each have an issue.
- Nightly: fuzzing, `sim-sweep`, `core/test/tla/run.sh small`, coverage.
- Behind features, off by default: iroh P2P (`iroh`, transport and node only), LAN announcements (`lan`). Tests of those run with `cargo test-net` (tier 2). QUIC and the redb file store are always built.

How to run:
- CLI: `cargo run --bin osis -- --help`; `osis -s DIR init`, writes, `osis serve` for a local host (notes/cli.md).
- Host: `osis -s DIR serve --admit open` (a node hosting, listening on UDP 4040); prints `quic://host:port#key`.
- Standard data scenarios: core/osis's `contact`, `event`, `notes`, `tags` tests in `cargo test --workspace`.
- Sim: `cargo run --bin sim-sweep -- --seeds N --budget-secs T`; replay a failing seed with `osis_sim::replay("<scenario>", <seed>)`.
- Models: `core/test/tla/run.sh small` (Java); their tests run in `cargo test --workspace`; `cargo run --bin roles-model`.

Known open (issues/): cost residues (perm-eval-cost, node-core-gaps, node-sequences-not-paged, crdt-seq-linearization-cost); rough edges (node-sync-gaps); api-deferred (queries are a design pass), in-memory-things; tests-unbuilt (10^4-seed sweep, model refactors).

- MVP scope (Tess): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: Tess and agent iterate by discussion. Notes mark what was Tess's decision, the agent's call or a proposal. Decisions waiting on Tess are issues tagged `tess-call`.

## Notes
- notes/architecture.md: crate map and DAG, fixed abstractions, error classes, build and test rules, dependency allowlist, osis-base and osis-schema surfaces, where each crate's notes live.
- notes/mvp-progress.md: the MVP final report and how to resume.
- notes/api-design.md: Tess's API philosophy and the checklist for any API change.
- notes/api.md: the designed API shape (sync data API, typed keys, watches, `Write` with `set`/`edit`, sharing and sync surface), fixed directions, footguns closed, rejected shapes.
- notes/data-model.md: tids, CBOR, large values, AK grammar, schema DSL sketch.
- notes/versioning.md: transition conventions, write policy, blessed paths for hard schema changes.
- notes/crdt.md: merge design reasons, anomalies, reference model, text size, worked examples.
- notes/permissions.md: permission rules' reasons, roles model findings, revocation reasoning, sharing patterns.
- notes/sync.md: sync and host reasons, limits, what a node learns about data it cannot read, policy defaults.
- notes/crypto.md: suite choices, costs, crates.
- notes/ephemeral.md: ephemeral data design and what is built (in-memory things and aspects, persistence, placements, undo, ephemeral commits held in memory at every node holding them, relay-only signals; values kept alive by their author's rewrites), expiry, the all-nodes predicate, heartbeats and the stranded flag.
- notes/chat.md: chat as built on design E (examples/chat), with costs.
- notes/tags.md: the standard core aspects (`name.0`, `body.0`, `tag.0`), tags as marked groups in a graph, sharing a tag per item through one nested roster, the confirmation guideline.
- notes/networking.md: transports (iroh, known addresses), official infrastructure, push wake-up proposal, risks.
- notes/local-store.md: encrypted local store and key-erasure deletion.
- notes/node.md: osis-engine and osis-node module layout, engine surface, store records, node-core readings.
- notes/cli.md: the `osis` command-line tool (command table, value syntax, JSON, exit codes).
- notes/std.md: the first-party schemas (notes, contacts, events), the time types, what was left out of vCard and iCalendar, the scenario tests.
- notes/testing.md: tiers, vectors, fuzzing, simulator, budgets, policy checks; notes/testing-map.md: the generated spec-to-test map.
- notes/app.md: the first-party app's design direction (facet views, lenses, state in osis, Masonry without Xilem, platform work, prototype order).
- notes/explainer.md: the docs site.
