# Overview and invariants
> Summary: What osis is, its four areas (API, data model, permissions, sync), and the hard invariants; decided by owner, formerly spec/README.md.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness. Target: end-user apps managing small amounts of interconnected data across users and devices (notes, calendars, spreadsheets). Multiple apps, app versions, generic tools and AI agents access the same data, like traditional file formats. Also handles device sync, sharing between users, encryption, and simple data APIs. Sits somewhere between Git, Obsidian, Google Drive and Syncthing.

## Areas
- **API** (notes/api.md): Rust API to search, read, write and listen for changes. Hides crypto, databases, networking and CRDTs as far as possible.
- **Data model** (notes/data-model.md, notes/serialization.md): every piece of data is an `Aspect` of a `Thing`. Things have 120-bit self-certifying tids; aspects are tid + aspect key (`AK`). Values are type-checked against the aspect's type.
- **Permissions** (notes/permissions.md): an `Actor` (user-like) controls multiple `Node`s (osis instances on devices). Actors are cryptographically identified and verified (no central auth). Each thing is owned by exactly one actor, fixed by its tid; hand-over is lazy (notes/permissions.md). Access is granted by membership in the owner actor, not per thing.
- **Sync** (notes/crdt-sync.md): each node tracks its own set of things and syncs with nodes with overlapping sets. Changes to aspects are grouped into commits, sent to nodes tracking the affected things and applied atomically. CRDTs resolve conflicts.

## Invariants
- No single registry of things; total things may exceed what any one system can track.
- Groups of things exist, but a thing may be in several groups. No "repo" concept.
- Data may be permanently deleted or modified. Nothing depends on retaining full history.
- Single canonical serialization, byte-identical across platforms and versions (hash stability).
- BLAKE3 is the only hash.

## Workflow (since 2026-09-25)
No spec directory. Owner and agent iterate by discussion; agent records decisions in notes, then implements. Notes mark items as decided or proposal.
