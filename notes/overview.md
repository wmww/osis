# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements, accepted limits and usage rules are spec/requirements.md. Significant or breaking spec changes need owner sign-off.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and pending owner decisions (`grep -l owner-call issues/*`). `plans/`: the implementation run. plans/mvp_meta.md is the entry point (roles, rules, order of work), notes/mvp-progress.md its resumption point; one plan per crate or subsystem, plans/protocol-spec.md (the TBDs in spec/), plans/testing.md and plans/tla-models.md (test strategy and model checking). `grep '^> Summary' plans/*.md` lists them.
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
- Design is settled apart from byte layouts and constants (plans/protocol-spec.md). The pre-implementation sweep (five reviews: permissions, key flows, blind nodes, CRDT, app developer) and the final pre-swarm review are folded in; what they changed is recorded in the notes' "why" and "Limits" sections.
- Code: Cargo workspace; crate map, layer DAG, fixed abstractions and build rules in notes/architecture.md, run state in notes/mvp-progress.md. Implemented and tested: osis-core, -crypto, -crdt (incl. sequences), -schema, -perm, -store, -commit, -keys, -label, -proto, test infrastructure (vectors/, fuzz/, osis-bench). In progress or skeletons: transport, server, node, osis, cli, sim. `models/`: `crdt` (reference model of spec/crdt.md; notes/crdt.md), `membership` (membership rules; notes/permissions.md), `tla` (TLA+ sync and rotation models; notes/testing.md).
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
- notes/explainer.md: the docs site.
