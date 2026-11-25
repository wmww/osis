# Settings: one private place per account and per node
> Summary: Settings are ordinary aspects on things only the account's nodes read: one account settings thing and per-node settings syncing among the account's nodes; windows are local things on the node root. Core's per-node settings are built as entries keyed by node thing on A (`caps^.0`, pointer `settings^.0`); the app's per-node settings, the account settings thing, windows and theme are not, and the node data thing below would be a second shape beside core's entries: settle one before building (accounts piece 6).
> Priority: normal
> Tags: api, app, kit, spec, tess-call

## Direction (Tess)
Per-node settings (`caps^.0`, `clients^.0` included) sync by default: the node data thing is referenced both from the account's shared data and from the local node root, so a node finds its own settings locally and its siblings find them through the account.

## Built (core)
A node's settings are its node thing's entries, keyed by it, on the thing its node root's `settings^.0` names (A, written at making and pairing; spec/sync-set.md §1): `caps^.0` is `map<weak, caps>` there, written by A's admins, read by `Engine::caps`. Not on N: A's write grant on N would close a key cycle (N holds admin on A, so the later grant is keyless and A's members read nothing of N).
- `clients^.0` stays on the node root (tess-call, departing from the direction above): an entry makes the node sign as N for the actor it names, so a sibling writing it could name N itself or another account of a linked node and sign as N. Moving it needs the node to act for an entry of S's only through S (paths starting at S, so the actor's rights are at most S's): a confinement `Osis::act_as` lacks today.

## Principle
A setting is an aspect on a thing only the account's nodes read. Privacy and sync come from where the thing sits; there is no settings protocol, store or merge rule. Everything the account keeps about one node is reached through one pointer from that node, and nothing else is keyed by node ID.

## Decided
- **Account settings thing**: a dependent of A, made once in the account's creation transaction and pointed to from A (`settings.0: weak`).
- **Node data thing** per node: a dependent of A, so any node of the account writes it (not on the node thing, which only its node writes). Its tid names no node; only the node's pointer links them. Created only by the node itself on first open, with a derived creation nonce (`kdf("node data", node seed, account tid)`, as a link key's), thing first, then pointer: a crash between repeats nothing. What holds the pointer is to restate: `node.0` is gone.
- **Reading**: a setting is this node's value, else the account's, else the caller's built-in default; any key at either level; defaults never written. API (to pass notes/api-design.md): `settings() -> Tid`, `node_data(node) -> Option<Tid>`, `setting(key)` resolved with one listener over both levels. Writes are ordinary `at(tid, key)` calls. Client port rows the node's only at first.
- A node applies its settings from listeners, including changes made while it was offline. A node of several accounts follows its main account's. Any node may change any other's settings (a remote change can cut a node off; only someone at it can fix that).
- **Windows**: each its own thing, any number per node, held by the node root: in no sync unit. Sharing one later is an ordinary grant plus a reference.
- **Node removal** drops A's strong to the node's data thing; a removed node reads built-in defaults.
- **Moves**: `ui:windows.0` (windows minted under home today) to node-root things (`libs/kit/src/store.rs` `window`, `window_opt`); `ui:theme.0`, `ui:mode.0` to the account settings thing. Favorites, arrangements and `viewed_as` stay (user data); process-only `Config`/`AppConfig` fields stay.
- Spec to update when built: spec/data-model.md §9 and `schema/core.osis`, spec/crypto.md §3 and spec/wire.md §3 (the nonce), `schema/ui.osis`.

## Tests (what users observe)
- A setting written on one node reads on another node of the account, and at neither through a peer of another account sharing a thing with it.
- `setting` resolves node, then account, then default; its listener fires on a change at either level, not on a write hidden behind the node's value.
- A crash between creating a node data thing and its pointer: the next open ends with one thing and a pointer.
- A window's content reaches no other node; two windows on one node keep separate state.
- A removed node's data thing is gone at the other nodes, and its later writes do not count.
