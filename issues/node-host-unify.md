# One kind of node
> Summary: There is no fundamental distinction between nodes by how much of their data they can read (Tess). Words are fixed by spec/requirements.md Terms; this lists what still separates them in code and notes, and what to decide about each. The same binary already runs every case; the remaining question is three serving paths, two stores and three keys on one node.
> Tags: node, sync, api, tess-call

**End state (Tess):** one concept of a node, and one of a peer: any node a group syncs with, readable to it or not. "Host" is historical and deprecated: in the remaining code, spec and notes it's a leftover to remove, never a concept to build on. Networking needs its own session (Tess), which owns this issue together with issues/no-server-audit.md, and turning on `iroh` and `lan` waits for it. Needs Tess's input on the open choices below.

An ordinary node (a laptop, a phone) may keep data it cannot read for others, and a backup machine may read some of what it holds (its settings, a website's data). Same binary, run the same way, any mix.

What already holds: hosting runs inside a node, from its `host.0^` (notes/sync.md, Hosting in the node), and there is no separate host program. So a laptop can already host, and a mostly encrypted machine already has an account and data of its own.

## Keep
The code that serves data a node may not read cannot decrypt anything (`osis-host` has no engine or keys, `tools/policy.py` `host_blind`). That is a security boundary inside every node, not a kind of node. Describe it that way.

## Still separated: decide each
1. **Two stores.** A node hosting a group it also reads keeps it twice: plaintext state in `db.redb`, blobs in `host.redb`.
2. **Three ways to serve a label.** The hub for hosting (`osis-host`), a peer that reads the label serving it (spec/sync.md §5, "serves it as its own host"), and hosts replicating to each other. Can a peer's serving and the hub be one path, differing only in what proof opens a label?
3. **Three listening keys.** Host address, dialable key and client listener key, each with its own rules, and the client port is never served on the host address (notes/client-port.md §5). Some of this is privacy (transport keys unlinkable from node keys), so keep what that needs and no more.
4. **Hosting is opt-in by `Serving` config.** Fine as a default. Check nothing assumes a host is always on or has a public address (Tess's laptop case), and that `Admit` isn't phrased around servers.
5. **`osis-proto` session names.** `ClientSession` means the dialing side of a connection, unrelated to a client of the API. `ServingSession::port_only` and friends likewise.

## No server assumed (Tess)
Requirements: spec/requirements.md, Decentralization. Known departures, in order:
1. **P2P is off in every build.** No manifest for the app, Android or CLI enables `iroh` or `lan`; only `cargo test-net` does. Turn both on by default, raising the Rust minimum to 1.91, and test real devices, Android included.
2. **Direct sync between users is off by default.** `reach.0` goes out only where every reader is this account or a contact, so a chat joined by link has none. Default to on. An open audience (public, bearer read) is the case to think about, as is what a user can do about address exposure without losing P2P.
3. **Recovery** is tied to having hosts (no card without them, key discarded), and is being reworked anyway: an explicit step, with `create` returning only the handle.
4. **Every feature with no hosts:** audited in issues/no-server-audit.md.

## Clients
A **client** is anything using the client protocol; a node may be one too (a phone syncing its private data and using another machine's node for bigger, less sensitive data). A **thin client** is a client that is not a node. Neither says what actor it acts as, and the model doesn't couple machine, transport and actor: there are many threat models, and which fits is a node's policy.

Default policy (Tess):
- **Unix socket**: open without authentication to the current user, as the node's main actor. There is no security boundary there anyway.
- **Localhost or network listener**: a client may act only as actors it has cryptographically authenticated for.

To build: a credential names the actor it acts as, the main one included if the node's owner chooses. Today the transport decides (socket: main actor; secret: an actor minted for it), and notes/client-port.md Rejected ("Thin nodes", now phrased as a default) argues from one threat model. Today's credential is a bearer secret inside TLS; decide whether "cryptographically authenticated" needs a signature by the actor's key instead. Also: acting as several actors in process, issues/grant-rename-multi-actor.md (public `act_as`).

## Spec needing a concept change, not a word change
Rule text still says "host" here, waiting on this issue and owner removal. Swapping the word would keep the picture:
- spec/overview.md Conventions: a label's hosts are "the addresses in its `label.0` record": a fixed list admins write, so a node is reachable as one only at a stable address.
- spec/sync.md §2, §10, spec/wire.md §10 (`Link`, `Card`): `label.0`, link and card host lists hold fixed addresses; `peer://` is never one (issues/no-server-audit.md rows 26, 27).
- spec/sync.md §4, §5, §6: two serving paths with different rules: host state and operations against a co-reader peer "serving it as its own host", with proof 3 refused at hosts. Item 2 above.
- spec/permissions.md §3 (complete pass waits on hosts, and on peers only for a bounded time) and §7 (recovery card and links name hosts): issues/no-server-audit.md rows 13-19.
- spec/data-model.md §9 (`host.0^`, `own`): admission by owner, also waiting on owner removal.
- spec/requirements.md: "a hiding host", "Nothing trusts a host's word", an inbox's budget "at a host": each is about a node serving data it cannot read.

## Two kinds of peer
The API says peer (issue api-refactor (closed)'s rename), and two things answer to it. A rename could not hide it: `add_peer` is a label's host under a new word. Honest for now (lib.rs says so): `saved_peers`, `SyncScope::AllWithSavedPeers`, `SyncState::{NoPeers, Connected}`.

| | Saved peer | Direct peer |
|---|---|---|
| Named by | fixed address in `label.0`, link and card text | `reach.0` (key, relays), LAN, a link's sharer |
| Who can be one | a node serving (`set_serving`, `Admit`), reader or not; a plain node has no such address | a node that reads the group |
| What it holds | blobs, in `host.redb` | plaintext state |
| Key | serving key | dialable key |
| Confirms | a pass: `Synced`, `wait_synced`, the pre-sync, `restore`, `complete` | nothing: `Connected` |

One kind of peer needs, in order of what it unblocks:
1. **One idea of a group's sources** (issues/no-server-audit.md Fixes 4): states, waits, the pre-sync and `complete` judged over saved and direct alike. Open for Tess: what `Required` promises when no single place holds all writes. No wire change. Most of the API's honesty comes from this.
2. **An address that names a node**: `peer://` in `label.0`, link and card hosts, dialed by key (spec/sync.md §10, spec/wire.md §10, rows 26, 27); one key to name a node by, or a reason for each (item 3 above).
3. **One serving path**: a reader serving a label and the hub, differing in what proof opens it (item 2; spec/sync.md §4-§6), and one store (item 1).
4. **Consent**: what `Admit` means once anyone may name any node as a peer (row 29, after owners).
5. **Finding carriers**: how holders learn of a non-reading carrier on a dynamic mesh (row 28, Fixes 7).

Then, in the API: `add_peer` takes any node, `peers(g)` is one list and `sync(g, peers)` adds to it, `set_serving` is only limits, `AllWithSavedPeers` becomes all, and `Connected` goes.

## Names left
The registry of every old word is issues/deprecated-terms.md; this list is the part this issue owns.
The public API, CLI, app and notes say node, peer, `Address`, serving, `SyncId`, account (`osis`'s notes/api.md). What still says otherwise waits for owner removal, as the owner work is in there:
- **Engine, perm, proto, `osis-host` names**: `label` and `LabelId`, `HostPolicy`, `host.0^`, `host.redb`, `Tier::Owner`, `Person`/`create_person`, `BatchId`, `Written`, `Mutation::expires` per aspect, `Edge`, `Hub`, `osis_label::ShareLink.hosts`, `CommitKind` beneath the API's, `Time` as `WallMs` by another name. The harness too (`World::add_host`, `Opening.hosts`, `hosts` in test helpers).
- **Spec rule text**: "host" and "label" throughout; "edge", "rights", "demotion" and "revocation" where a role is meant, one word of "part" and "delta", and "placed" (membership words; a commit held at a host: "uploaded"). The concept changes are the list above.
- `required.0^`'s schema field `keep` (core.osis, spec/data-model.md §9, `osis get`): the API's `RequiredRules::retain_copies` wraps it; rename with the spec's "saying keep" in spec/permissions.md §2, §3.
- **"Sync ID" over "label"**: engine and spec take the word then too. Today the `SyncId` type is an opaque label ID.
- `sync(thing, &peers)`: a sync ID of its own is mostly a detail of how a thing travels; Tess is unsure how much to encourage single-thing ones. The doc steers sets through a group, and only `make_link` makes one quietly. Reconsider with the peers work.
- Rendered docs: `lib.rs` keeps no spec citations. A doc-only module embedding spec/ with `#[doc = include_str!(..)]` would give links; not tried, and `tools/gate.sh` would then need that file in its docs step.
