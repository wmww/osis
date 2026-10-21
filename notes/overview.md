# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. Until a stable release, spec edits need no owner sign-off; changes to or conflicts with spec/requirements.md go to the owner.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and pending owner decisions (`grep -l owner-call issues/*`); each has Summary, Tags and a Repro line. Tags: `security`, `performance`, `tests`, `post-mvp`, `owner-call`, component names. `plans/`: work not done yet; the MVP plans are all done or turned into issues. notes/mvp-progress.md holds the MVP final report.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
The MVP is built: every subsystem of the spec is implemented and tested (final report, deviations and open issues: notes/mvp-progress.md). Design is settled; byte layouts are in spec/wire.md (vectors FC-1..FC-3 frozen, the rest provisional).

Code map (crate DAG and rules: notes/architecture.md):
- `crates/`: osis-core (values, CBOR, ids, chunker), -crypto, -crdt, -schema, -perm, -store (encrypted local store), -commit, -keys, -label (blobs, labels, steps, large values), -proto (sans-I/O sync protocol), -transport (in-process, QUIC, iroh, LAN), -server (blind node), -node (engine, sync engine, membership flows), `osis` (the app API), osis-cli (binary `osis`), osis-bench.
- `examples/` notes-app, chat, folder (notes/apps.md); `sim/` the deterministic simulator (notes/testing.md); `vectors/` conformance vectors; `fuzz/` cargo-fuzz targets; `models/` crdt and membership reference models, TLA+ `sync` and `rotation`; `tools/` policy.py, spec_map.py, fixpoint.

What runs where (details and latest numbers: notes/testing.md):
- Tier 1, `cargo test --workspace`: everything below the sim's long scenarios; green.
- Tier 2, `cargo test --release --workspace -- --ignored --skip sweep`: scale checks, budgets, long sim scenarios, the localhost CLI session; known failures each have an issue.
- Nightly: fuzzing, `sim-sweep`, `models/tla/run.sh small`, coverage.
- Behind features, off by default: QUIC (`quic`; the CLI and server binary have it on), the redb file store (`file-store`/`file-backend`), iroh P2P (`iroh`, transport and node only), LAN announcements (`lan`). Tests of those run with `--features` (tier 2).

How to run:
- CLI: `cargo run -p osis-cli -- --help`; `osis -s DIR init`, writes, `osis serve` for a local server (notes/cli.md).
- Server: `cargo run -p osis-server --features bin -- --help` (or `osis serve`); prints `quic://host:port#key`.
- Examples: `cargo run -p notes-app` (or chat, folder); `cargo test -p chat`.
- Sim: `cargo run --release -p osis-sim --bin sim-sweep -- --seeds N --budget-secs T`; replay a failing seed with `osis_sim::replay("<scenario>", <seed>)`.
- Models: `models/tla/run.sh small` (Java); `cargo test -p crdt-model`, `-p membership-model`.

Known open (issues/): owner tradeoffs stated in user terms (token-admin-secret, header-list-commitments, reseal-triggers, store-concurrent-readers, ledger-same-ts-commits, crdt-undo-absent-positions); cost residues (perm-eval-cost, node-core-gaps, node-sequences-not-paged, crdt-seq-linearization-cost, keep-at-most-partial-bodies); rough edges (import-over-max-delta-bare, node-sync-gaps, p2p-followups, reading-candidates-unknown-authors); api-deferred (queries are a design pass); tests-unbuilt (10^4-seed sweep, model refactors).

- MVP scope (owner): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: owner and agent iterate by discussion. Notes mark what was the owner's decision, the agent's call or a proposal. Decisions waiting on the owner are issues tagged `owner-call`.

## Notes
- notes/architecture.md: crate map and DAG, fixed abstractions, error classes, build and test rules, dependency allowlist, osis-core and osis-schema surfaces, where each crate's notes live.
- notes/mvp-progress.md: the MVP final report and how to resume.
- notes/api.md: the designed API shape (sync data API, typed keys, watches, `Write` with `set`/`edit`, sharing and sync surface), fixed directions, footguns closed, rejected shapes.
- notes/data-model.md: tids, CBOR, large values, namespaces, schema DSL sketch.
- notes/versioning.md: transition conventions, write policy, blessed paths for hard schema changes.
- notes/crdt.md: merge design reasons, anomalies, reference model, text size, worked examples.
- notes/permissions.md: permission rules' reasons, membership model findings, move (copy) and revocation reasoning, sharing patterns.
- notes/sync.md: sync and blind-node reasons, limits, what a blind node learns, policy defaults.
- notes/crypto.md: suite choices, costs, crates.
- notes/ephemeral.md: signals vs expiry vs the all-nodes predicate, heartbeats and the stranded flag.
- notes/chat.md: the chat pattern derived from the current design, with costs.
- notes/networking.md: transports (iroh, direct servers), official infrastructure, push wake-up proposal, risks.
- notes/local-store.md: encrypted local store and key-erasure deletion.
- notes/node.md: osis-node module layout, engine surface, store records, node-core readings.
- notes/cli.md: the `osis` command-line tool (command table, value syntax, JSON, exit codes).
- notes/apps.md: the example apps, their end-to-end tests and findings.
- notes/testing.md: tiers, vectors, fuzzing, simulator, budgets, policy checks; notes/testing-map.md: the generated spec-to-test map.
- notes/explainer.md: the docs site.
