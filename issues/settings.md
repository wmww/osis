# Account and node settings
> Summary: Build plan (design decided with Tess): settings are ordinary aspects on one private thing for the account and one for each node, both items of home, so they sync among the account's nodes and nobody else reads them. A node's `node.0` points to its data thing, the one place for per-node data; windows stay separate local things. Adds a place and moves misplaced state; adds no new settings.
> Priority: normal
> Tags: api, app, kit, spec

## Principle
A setting is an aspect on a thing in the account's home. Privacy and sync come from home; there is no settings protocol, store or merge rule. Everything the account keeps about one node is reached through that node's `node.0`, and nothing else is keyed by node ID.

## Structure
```
home
├─ settings.0: tid                     → account settings thing
└─ group.0 items: account settings thing, each node's data thing

node thing
└─ node.0: struct { software 0, data 1: tid }  → node data thing

node data thing
├─ this node's settings (aspects)
├─ other per-node data that syncs among the account's nodes
└─ ui:windows.0: set<tid>              → local window things
```
- **Home** is the group every node of the account syncs and only they read: the account thing today, D's home label under issues/account-signing.md. Write the code against home so that move changes nothing here.
- **Account settings thing**: plain, first admin the account. `Osis::create` makes it, lists it in home and sets `settings.0` in one ordinary commit before returning, when no other node exists, so it cannot be made twice.
- **Node data thing**: plain, first admin the account, so any node of the account writes it. Item of home.
  - Not on the node thing: a node thing is written only by that node (spec/permissions.md §1), which rules out remote edits.
  - Not on D: reading D opens the account's epoch seeds, so anything there could never be shared.
  - Its tid names no node and only `node.0` links them, so granting a role on it later does not reveal a device.
- **Creating a node data thing**: the node itself, on first open as a node of the account, is the only creator. Its creation nonce is `kdf("node data", node seed, account tid)` (as link and recovery keys derive theirs, spec/crypto.md §3). `node.0` writes are commits of their own, so the thing and the pointer are two commits: on open, make the thing unless held, then write the pointer if absent. A crash between them repeats nothing and leaves no stray thing.
- **One thing per node, not a group**: nothing needs several synced per-node things yet. If something does, the data thing gains `group.0` and keeps its tid.

## Reading and writing
- A setting's value is this node's value, else the account's, else the caller's built-in default. Any key may be set at either level; settings declare no scope.
- Defaults are never written to osis.
- API, to pass notes/api-design.md: `settings() -> Tid`, `node_data(node) -> Option<Tid>` (`None` until that node's `node.0` is held), and `setting(key)`: the resolved value with one listener over both levels, firing when the resolved value changes. Writes and clears are the ordinary `at(tid, key)` calls.
- Client port rows are the main actor's only at first (not in `method::for_client`). A client with its own actor reads settings only if granted a role, as for any thing.
- A node applies its settings from listeners or engine changes, as it does `host^.0` now, including changes made elsewhere while it was offline.
- Limit: a node of several accounts follows its main account's settings.
- Limit: any node of the account can change any other's settings, as it can already act as the account. A remote change can cut a node off the network; then only someone at that device can fix it.
- Limit: until account-signing step 7, `node.0` still goes under shared labels, so co-readers see the data thing's random tid; they cannot open it.

## Windows
- A window is its own thing, any number per node, in no synced group: its state never leaves the device.
- `ui:windows.0` on the node data thing lists them. The list syncs; other nodes see tids they cannot resolve.
- Create the window, then add it to the list, in **two commits**: a commit travels whole (notes/whole-commits.md), and a part on an unsynced thing inside a synced commit must not leave the node. A crash between them leaves one unused local window.
- Sharing a window later is adding it to a synced group or granting a role; a first grant also syncs it among the account's nodes (notes/api.md, Sharing and roles).

## Node removal
`remove_node` deletes the node's data thing and its home membership. The node's windows were only ever on that device. A removed node that loses home reads built-in defaults, so with `host^.0` gone it stops hosting.

## What moves
- `host^.0` and `clients^.0`: from the node thing to the node data thing. Drop "never placed under a label" from spec/data-model.md §9. Keep the `^`, so a later write grant on the thing does not carry hosting. The host secret stays a local record.
- Windows: `ui:windows.0` moves from the account group to the node data thing as a set. Remove the window map entry logic and `ui:internal.0` with its subgroup (`libs/kit/src/store.rs`, `window` and `window_opt`).
- `ui:theme.0`, `ui:mode.0`: from the account group to the account settings thing, removing their first-set-wins handling.
- Stay: favorites, arrangements and `viewed_as` (the user's data, not settings); `Config` and `AppConfig` fields that describe one running process.

## Not now
- New settings. `direct_sync` and `relays` are future candidates: `create` would have to take initial values, so a node that must not show its address is private from its first moment.
- Device-only settings. Nothing prevents them: a local thing listed on the node data thing as windows are, read before the node's value.

## Spec and notes to update
- spec/data-model.md §9 and `schema/core.osis`: `settings.0`, `node.0`'s `data` field, where `host^.0` and `clients^.0` live. spec/crypto.md §3 and spec/wire.md §3: the derived nonce.
- notes/serving.md (remote configuration), notes/api.md, notes/app.md and `schema/ui.osis` (windows, look), notes/growth.md (check for a new row).
- issues/app-group-helper.md: drop theme and mode from its duplicate rules.

## Tests (what users observe)
- A setting written on one node reads on another node of the account, and at neither through a peer of another account sharing a thing with it.
- `setting` resolves node, then account, then default; its listener fires on a change at either level and not on a write hidden behind the node's value.
- A sibling changes a node's `host^.0` while that node is offline; it hosts accordingly once synced.
- A crash between creating a node data thing and its pointer: the next open ends with one thing and a pointer.
- A local window's content reaches no other node, and two windows on one node keep separate state.
- A removed node's data thing is gone at the other nodes, and its later writes do not count.
