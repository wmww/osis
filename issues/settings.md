# Settings: one private place per account and per node
> Summary: Settings are ordinary aspects on things only the account's nodes read: one account settings thing and one data thing per node, syncing among the account's nodes; windows are local things on the node root. Adds a place and moves misplaced state, no new settings. The anchors were designed on the deleted account root and `node.0`: restate them on the account thing A (accounts pieces 2 and 6, notes/accounts-switch-brief.md) before building.
> Priority: normal
> Tags: api, app, kit, spec

## Direction (Tess)
Per-node settings (`caps^.0`, `clients^.0` included) sync by default: the node data thing is referenced both from the account's shared data and from the local node root, so a node finds its own settings locally and its siblings find them through the account. Today `caps^.0`/`clients^.0` sit on the local node root (spec/sync-set.md §1: simpler, and reversible); building settings moves them.

## Principle
A setting is an aspect on a thing only the account's nodes read. Privacy and sync come from where the thing sits; there is no settings protocol, store or merge rule. Everything the account keeps about one node is reached through one pointer from that node, and nothing else is keyed by node ID.

## Decided
- **Account settings thing**: a dependent of A, made once in the account's creation transaction and pointed to from A (`settings.0: weak`).
- **Node data thing** per node: a dependent of A, so any node of the account writes it (not on the node thing, which only its node writes). Its tid names no node; only the node's pointer links them. Created only by the node itself on first open, with a derived creation nonce (`kdf("node data", node seed, account tid)`, as a link key's), thing first, then pointer: a crash between repeats nothing. What holds the pointer is to restate: `node.0` is gone.
- **Reading**: a setting is this node's value, else the account's, else the caller's built-in default; any key at either level; defaults never written. API (to pass notes/api-design.md): `settings() -> Tid`, `node_data(node) -> Option<Tid>`, `setting(key)` resolved with one listener over both levels. Writes are ordinary `at(tid, key)` calls. Client port rows main actor only at first.
- A node applies its settings from listeners, including changes made while it was offline. A node of several accounts follows its main account's. Any node may change any other's settings (a remote change can cut a node off; only someone at it can fix that).
- **Windows**: each its own thing, any number per node, held by the node root: in no sync unit. Sharing one later is an ordinary grant plus a reference.
- **Node removal** drops A's strong to the node's data thing; a removed node reads built-in defaults.
- **Moves**: `caps^.0`, `clients^.0` to the node data thing; `ui:windows.0` (windows minted under home today) to node-root things (`libs/kit/src/store.rs` `window`, `window_opt`); `ui:theme.0`, `ui:mode.0` to the account settings thing. Favorites, arrangements and `viewed_as` stay (user data); process-only `Config`/`AppConfig` fields stay.
- Spec to update when built: spec/data-model.md §9 and `schema/core.osis`, spec/crypto.md §3 and spec/wire.md §3 (the nonce), `schema/ui.osis`.

## Tests (what users observe)
- A setting written on one node reads on another node of the account, and at neither through a peer of another account sharing a thing with it.
- `setting` resolves node, then account, then default; its listener fires on a change at either level, not on a write hidden behind the node's value.
- A crash between creating a node data thing and its pointer: the next open ends with one thing and a pointer.
- A window's content reaches no other node; two windows on one node keep separate state.
- A removed node's data thing is gone at the other nodes, and its later writes do not count.
