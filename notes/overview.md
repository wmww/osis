# Overview and invariants
> Summary: What osis is and its four areas (API, data model, permissions, sync); invariants moved to notes/constraints.md. Decided by owner, formerly spec/README.md.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness. Target: end-user apps managing small amounts of interconnected data across users and devices (notes, calendars, spreadsheets). Multiple apps, app versions, generic tools and AI agents access the same data, like traditional file formats. Also handles device sync, sharing between users, encryption, and simple data APIs. Sits somewhere between Git, Obsidian, Google Drive and Syncthing.

## Areas
- **API** (notes/api.md): Rust API to search, read, write and listen for changes. Hides crypto, databases, networking and CRDTs as far as possible.
- **Data model** (notes/data-model.md, notes/serialization.md): every piece of data is an `Aspect` of a `Thing`. Things have 120-bit self-certifying tids; aspects are tid + aspect key (`AK`). Values are type-checked against the aspect's type.
- **Permissions** (notes/permissions.md): an `Actor` (user-like) controls multiple `Node`s (osis instances on devices). Actors are cryptographically identified and verified (no central auth). Each thing is owned by exactly one actor, fixed by its tid. Access is membership in the owner actor or membership edges on the thing itself; hand-over (lazy, new tid) only moves a thing out of its owner's tree (notes/permissions.md).
- **Local store** (notes/local-store.md): backends hold ciphertext only; unit keys hang off a key tree rooted in platform erasable storage, so deletion is key erasure.
- **Sync** (notes/sync.md, notes/crdt-sync.md): each node tracks groups and syncs them with other nodes by reconciling sets of encrypted commit blobs. Keyless nodes (backup servers) take part without seeing structure. Commits apply atomically; CRDTs resolve conflicts.

## Invariants
See notes/constraints.md: all hard constraints, goals and the known tensions between them, in one place.

## Workflow (since 2026-09-25)
No spec directory. Owner and agent iterate by discussion; agent records decisions in notes, then implements. Notes mark items as decided or proposal.
