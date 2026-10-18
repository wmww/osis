# Overview
> Summary: Project state, where things live (spec vs notes vs issues), the code so far, MVP scope, and the index of notes.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness: end-user apps managing small-to-large interconnected data across users and devices (notes, calendars, spreadsheets), shared by many apps, app versions, generic tools and AI agents like a file format. Handles device sync, sharing, encryption and simple data APIs. Somewhere between Git, Obsidian, Google Drive and Syncthing.

## Where things live
- `spec/`: what a compatible implementation needs (start at spec/overview.md). Requirements and tensions are spec/requirements.md. Significant or breaking spec changes need owner sign-off.
- `notes/`: why the spec is what it is, rejected alternatives, policies and implementation hints.
- `issues/`: unsolved problems and pending owner decisions (`grep -l owner-call issues/*`). `plans/`: plans/protocol-spec.md (byte layouts and remaining protocol gaps, the TBDs in spec/).
- `docs/explainer/`: slide-deck site (notes/explainer.md), updated only on request.

## Status
- Design is settled apart from byte layouts and constants (plans/protocol-spec.md) and the open issues.
- Code: `crdt-model/` (reference model for spec/crdt.md, not the implementation; notes/crdt.md) and `tools/fixpoint/` (throwaway model of the membership rules; notes/permissions.md). No implementation yet.
- MVP scope (owner): everything in the spec. Only unimportant non-protocol client features may slip (e.g. client support for the anonymous-writing patterns).
- Workflow: owner and agent iterate by discussion. Notes mark what was the owner's decision, the agent's call or a proposal. Decisions waiting on the owner are issues tagged `owner-call`.

## Notes
- notes/api.md: fixed API directions, sketch, queries apps need, move resolution, diagnostics.
- notes/data-model.md: tids, CBOR, large values, namespaces, schema DSL sketch.
- notes/versioning.md: transition conventions, write policy, blessed paths for hard schema changes.
- notes/crdt.md: merge design reasons, anomalies, reference model, text size, worked examples.
- notes/permissions.md: permission rules' reasons, fixpoint findings, move (copy) and revocation reasoning, sharing patterns.
- notes/sync.md: sync and blind-node reasons, limits, what a blind node learns, policy defaults.
- notes/crypto.md: suite choices, costs, crates.
- notes/ephemeral.md: signals vs expiry vs the all-nodes predicate.
- notes/networking.md: transports (iroh, direct servers), official infrastructure, push wake-up proposal, risks.
- notes/local-store.md: encrypted local store and key-erasure deletion.
- notes/explainer.md: the docs site.
