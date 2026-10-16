# Overview
> Summary: What osis is, its areas and which note covers each. Constraints and tensions live in notes/constraints.md.

osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness. Target: end-user apps managing small amounts of interconnected data across users and devices (notes, calendars, spreadsheets). Multiple apps, app versions, generic tools and AI agents access the same data, like traditional file formats. Also handles device sync, sharing between users, encryption, and simple data APIs. Sits somewhere between Git, Obsidian, Google Drive and Syncthing.

## Areas
- **API** (notes/api.md): Rust API to search, read, write and listen for changes. Hides crypto, databases, networking and CRDTs as far as possible.
- **Data model** (notes/data-model.md, notes/serialization.md): every piece of data is an `Aspect` of a `Thing`. Things have 120-bit self-certifying tids; aspects are tid + aspect key (`AK`). Values are type-checked against the aspect's type and serialized as canonical CBOR.
- **Versioning** (notes/versioning.md): the wire only grows; app types are views; a representation change is a transition to new IDs (`succeeds`); which form is written is runtime policy; unknown data is parked, never dropped.
- **Permissions** (notes/permissions.md): an `Actor` (user-like) controls multiple `Node`s (osis instances on devices). Actors are cryptographically identified and verified (no central auth). Each thing is owned by exactly one actor, fixed by its tid. Access is membership in the owner actor or membership edges on the thing itself; hand-over (lazy, new tid) only moves a thing out of its owner's tree. Share links are invites (a link actor plus a link key).
- **Merge** (notes/crdt-sync.md): per-aspect delta-state CRDTs, one rule everywhere (timestamp plus author dot, later wins, removal is a reset); retention classes and purge.
- **Sync** (notes/sync.md): each node tracks groups and syncs them with other nodes by reconciling sets of encrypted commit blobs under per-group labels. Keyless (blind) nodes take part without seeing structure. Commits apply atomically.
- **Networking** (notes/networking.md): sync runs over our own transport abstraction; direct server connections without iroh, iroh for P2P (LAN, relays, later BLE); official blind server and relays; addresses and relays are osis data, transport keys separate from node keys.
- **Local store** (notes/local-store.md): backends hold ciphertext only; unit keys hang off a key tree rooted in platform erasable storage, so deletion is key erasure.
- **Ephemeral data** (notes/ephemeral.md): signals are never stored and reach only connected nodes; state may expire at a time every node honors; "all nodes" is a predicate over node-published state, never a protocol condition.

## Workflow
Owner and agent iterate by discussion; the agent records decisions in notes (marked decided or proposal, with dates), then implements. No code yet (2026-10-15).
