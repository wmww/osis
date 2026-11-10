# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and how to find a note.

osis (Open Structured Information System) is a decentralized data layer optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and their machines (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
The repo is meant to become a small monorepo of projects worked on independently (Tess): core (with cli and schema), `libs/` (what some but not all users of osis want: chat, the kit UI toolkit) and app (notes/app.md), each with its own checks (the gate picks them by changed paths, notes/build.md).
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. A design that cannot meet an item gets no footnote: the item is changed to say what actually holds. Until a stable release, spec edits need no Tess's sign-off; changes to or conflicts with spec/requirements.md go to Tess.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and decisions pending with Tess (`grep -l tess-call issues/*`); each has Summary, Priority (`grep -l 'Priority: critical' issues/*`) and Tags lines. Tags: `security`, `performance`, `tests`, `tess-call`, component names.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
The MVP is built: every subsystem of the spec is implemented and tested. Requirements not yet met: forward-secure deletion on disks that remap writes (issues/root-key-erasure-tier.md); some operations still O(state) or O(history) (issues tagged `performance`); "runs in browsers" (no wasm build, browser transport or store) and push wake-ups for sleeping devices (a proposal, notes/networking.md) unbuilt; API conveniences in issues/api-deferred.md. Design work in progress: first admins and admin disputes (notes/disputes-plan.md); open design questions for Tess are issues tagged `tess-call`. Byte layouts are in spec/wire.md; conformance vectors are all provisional until the first stable release (nothing is frozen or logged as a format change before then).

Code map (crate DAG and rules: notes/architecture.md):
- `core/` (package names keep the `osis-` prefix): `base` osis-base (values, CBOR, ids, chunker), -crypto, -crdt, -schema, -perm, -store (encrypted local store), -commit, -keys, -label (blobs, labels, steps, large values), -proto (sans-I/O sync protocol), -transport (in-process, QUIC, P2P, LAN), -host (serving), -node (engine, sync engine, role flows), `osis` (the app API), `bench` osis-bench. `libs/chat` osis-chat. `cli/` osis-cli (binary `osis`).
- `libs/kit/` osis-kit (UI toolkit over Masonry) and `app/` osis-app (binary `osis-app`, prototype notes app): workspace members outside default-members: built only when named (notes/app.md).
- `schema/` the first-party schema files, their scenario tests in core/osis's test binary (notes/std.md); `core/test/sim/` the deterministic simulator (notes/testing.md); `core/test/vectors/` conformance vectors; `core/test/fuzz/` cargo-fuzz targets; `core/test/crdt-model`, `core/test/roles-model` and `core/test/held-model` reference models, `core/test/tla` TLA+ `sync`, `rotation` and `roles`; `tools/` policy.py, spec_map.py, fixpoint.

How to run:
- CLI: `cargo run --bin osis -- --help`; `osis -s DIR init`, writes, `osis serve` to keep a node running (notes/cli.md).
- Serving for others: `osis -s DIR serve --admit open` (listens on UDP 4040); prints its address, `quic://IP:PORT#KEY`.
- Standard data scenarios: core/osis's `contact`, `event`, `notes`, `tags` tests in `cargo test`.
- Sim: `cargo run --bin sim-sweep -- --seeds N --budget-secs T`; replay a failing seed with `osis_sim::replay("<scenario>", <seed>)`.
- Models: `core/test/tla/run.sh <module>` (Java); their tests run in `cargo test`; `cargo run --bin roles-model`.

Open work: issues/, by their Priority lines.

- MVP scope (Tess): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: Tess and agent iterate by discussion. Notes mark what was Tess's decision, the agent's call or a proposal. Decisions waiting on Tess are issues tagged `tess-call`.

## Notes
Each note's first line is its summary: `grep '^> Summary' notes/*.md`. Sections that group several: notes/sync.md (sync), notes/engine.md (engine-*). Questions for Tess are issues tagged `tess-call`; notes/handoff.md holds state for the next coordinator; notes/testing-map.md is the generated spec-to-test map.

## Long-term direction (Tess)
Dogfood osis for the project's own coordination: Claudes working on osis coordinate over it (a realm), notes become osis documents, agents message each other and post to channels, and Tess sees and joins it in the app. Near term the core comes first; apps, UX and other use cases follow once it is solid.
