# Settings: one private thing per account and per node
> Summary: Build plan (design decided with Tess, restated in reference graph terms): settings are ordinary aspects on a private account settings thing, plus a node data thing per node, both plain things under the account root, so they sync among the account's nodes and nobody else reads them. A node's `node.0` points to its data thing; windows are local things on the node root. Adds a place and moves misplaced state; adds no new settings. Tess's direction: per-node settings sync by default, referenced from both the account's shared data and the local node root, so either finds them; easy to change or make configurable later.
> Priority: normal
> Tags: api, app, kit, spec

## Direction (Tess)
Per-node settings (`caps^.0`, `clients^.0` included) sync by default: the node data thing is referenced both from the account's shared data (D) and from the local node root, so a node finds its own settings locally and its siblings find them through D. Today `caps^.0`/`clients^.0` sit on the local node root (issues/reference-graph.md, Settled); building settings moves them.

## Principle
A setting is an aspect on a thing only the account's nodes read. Privacy and sync come from where the thing sits; there is no settings protocol, store or merge rule. Everything the account keeps about one node is reached through that node's `node.0`, and nothing else is keyed by node ID.

## Structure
```
account root D (holds.0)
├─ settings.0: weak                    → account settings thing (also a strong in holds.0)
└─ strongs: account settings thing, each node's data thing

node thing
└─ node.0: struct { software 0, data 1: weak }  → node data thing

node data thing
├─ this node's settings (aspects)
└─ other per-node data that syncs among the account's nodes

node root (local, holds.0)
└─ ui:windows.0 things                 → local window things
```
- **Account settings thing**: plain, made under the account root (its keys derive from D's, so P's nodes read it). `Osis::create` makes it, references it from D and sets `settings.0` in the account's creation transaction, so it cannot be made twice.
- **Node data thing**: plain, made under the account root, so any node of the account writes it.
  - Not on the node thing: a node thing is written only by that node (spec/permissions.md §1), which rules out remote edits.
  - Not D's own aspects: reading D opens the account's tickets, so anything there could never be shared.
  - Its tid names no node and only `node.0` links them, so granting a role on it later does not reveal a device.
- **Creating a node data thing**: the node itself, on first open as a node of the account, is the only creator. Its creation nonce is `kdf("node data", node seed, account tid)` (as a link key derives its own, spec/crypto.md §3). The thing with D's strong to it, then the pointer: on open, make the thing unless held, then write the pointer if absent. A crash between them repeats nothing and leaves no stray thing.

## Reading and writing
- A setting's value is this node's value, else the account's, else the caller's built-in default. Any key may be set at either level; settings declare no scope.
- Defaults are never written to osis.
- API, to pass notes/api-design.md: `settings() -> Tid`, `node_data(node) -> Option<Tid>` (`None` until that node's `node.0` is held), and `setting(key)`: the resolved value with one listener over both levels, firing when the resolved value changes. Writes and clears are the ordinary `at(tid, key)` calls.
- Client port rows are the main actor's only at first (not in `method::for_client`). A client with its own actor reads settings only if granted a role, as for any thing.
- A node applies its settings from listeners or engine changes, including changes made elsewhere while it was offline.
- Limit: a node of several accounts follows its main account's settings.
- Limit: any node of the account can change any other's settings, as it can already act as the account. A remote change can cut a node off the network; then only someone at that device can fix it.

## Windows
- A window is its own thing, any number per node, held by the node root's `holds.0`: in no sync unit, its state never leaves the device.
- Sharing a window later is granting a role on it and referencing it from a shared thing.

## Node removal
`remove_node` removes D's strong to the node's data thing, which releases it everywhere. The node's windows were only ever on that device. A removed node reads built-in defaults.

## What moves
- `caps^.0` and `clients^.0`: the plan wanted them on the node data thing (a sibling changes an offline node's caps); spec/sync-set.md §1 puts them on the local node root. Settle first (issues/reference-graph.md, To settle).
- Windows: `ui:windows.0` and `ui:internal.0` go; windows are node-root things (`libs/kit/src/store.rs`, `window` and `window_opt`).
- `ui:theme.0`, `ui:mode.0`: to the account settings thing, removing their first-set-wins handling.
- Stay: favorites, arrangements and `viewed_as` (the user's data, not settings); `Config` and `AppConfig` fields that describe one running process.

## Not now
- New settings. Whether a node listens for others and which relays it uses (no `Config` field today) are future candidates: `create` would have to take initial values, so a node that must not show its address is private from its first moment.
- Device-only settings: a local thing on the node root, read before the node's value.

## Spec and notes to update
- spec/data-model.md §9 and `schema/core.osis`: `settings.0`, `node.0`'s `data` field. spec/crypto.md §3 and spec/wire.md §3: the derived nonce.
- notes/api.md, notes/app.md and `schema/ui.osis` (windows, look), notes/growth.md (check for a new row).

## Tests (what users observe)
- A setting written on one node reads on another node of the account, and at neither through a peer of another account sharing a thing with it.
- `setting` resolves node, then account, then default; its listener fires on a change at either level and not on a write hidden behind the node's value.
- A crash between creating a node data thing and its pointer: the next open ends with one thing and a pointer.
- A local window's content reaches no other node, and two windows on one node keep separate state.
- A removed node's data thing is gone at the other nodes, and its later writes do not count.
