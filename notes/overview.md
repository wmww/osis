# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. Significant or breaking spec changes need owner sign-off.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and pending owner decisions (`grep -l owner-call issues/*`); each says how to reproduce it. `plans/`: work not done yet. plans/mvp_meta.md was the MVP run's entry point (roles, rules, order of work), notes/mvp-progress.md its resumption point; the plans still open are plans/hardening-signoff.md (next), plans/sim.md (sweep green at 10^4 seeds), plans/large-values.md (chunk reuse, scale test), plans/testing.md (strategy items not built) and plans/tla-models.md (one owner call, target 3). `grep '^> Summary' plans/*.md` lists them.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
- Design is settled; byte layouts and constants are in spec/wire.md. The pre-implementation sweep (five reviews: permissions, key flows, blind nodes, CRDT, app developer) and the final pre-swarm review are folded in; what they changed is recorded in the notes' "why" and "Limits" sections.
- Code: Cargo workspace; crate map, layer DAG, fixed abstractions and build rules in notes/architecture.md, run state in notes/mvp-progress.md. Waves 0-5 are merged: every crate of the map is implemented and tested (osis-core, -crypto, -crdt, -schema, -perm, -store, -commit, -keys, -label, -proto, -transport (in-process, QUIC, iroh behind a feature), -server (blind node over QUIC), -node (engine, sync engine, membership flows), the `osis` API, the `osis` CLI), three example apps (notes-app, chat, folder) with end-to-end tests, the simulator (phases A-C: harness, blind servers, scenario library, adversaries, version skew, nightly sweep), vectors (FC-1..FC-3 frozen, the rest provisional), fuzz targets, models (`crdt`, `membership`, TLA+ `sync` and `rotation`). Tier 1 (`cargo test --workspace`) is green in about 70 s of test time; tier 2 (`--release -- --ignored`) has the known failures listed in notes/testing.md, each with its issue. Known open: chat costs over their design budget, P2P without a LAN loop or one driver for servers and peers (issues/p2p-deferred.md), cost issues (perm, crdt sequences and paths, node passes). Next: plans/hardening-signoff.md.
- MVP scope (owner): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: owner and agent iterate by discussion. Notes mark what was the owner's decision, the agent's call or a proposal. Decisions waiting on the owner are issues tagged `owner-call`.

## Notes
- notes/architecture.md: crate map and DAG, fixed abstractions, error classes, build and test rules, dependency allowlist, osis-core and osis-schema surfaces, where each crate's notes live.
- notes/mvp-progress.md: state of the MVP run.
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
