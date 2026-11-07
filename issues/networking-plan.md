# Plan: networking and sharing
> Summary: The plan to get networking and sharing into a good state: one kind of node and one kind of peer, every feature working with no server, role and sync paired, honest status, then the spec and code rename (host, label, placed). Phases in order, each with the audit rows it fixes and what is unsure. Evidence: issues/no-server-audit.md. Owns the order of all networking work.
> Priority: normal
> Tags: node, sync, api, spec, tess-call

Written as a plan for others to carry out. **Unsure** marks what is open: (Tess) her call, (design) to work out when the phase starts, (implementor) settle in the code. Row numbers are issues/no-server-audit.md's. Requirements: spec/requirements.md, Decentralization and Offline and network.

## End state
- One concept of a node and one of a peer: any node a group syncs with, whether or not it can read the data. "Host" is gone from spec, code and notes (Tess).
- Every feature works with no server, relay or internet, only nodes that sometimes reach each other: on a LAN, on a dynamic mesh, through any willing node.
- Holding a role is what lets a node sync the thing: no "role but no route" state (below, Model).
- Status and waits say only what is true: "synced" means caught up with every node connected on the group (Tess), and nothing claims a delivery that did not happen.
- Spec and code use the current words; sync IDs are not in the public API.

## Words (target)
| Old | New | Notes |
|---|---|---|
| host, hosts, hosting | peer; a node **serves** or **carries** a group | "carrier" for a peer that holds data it cannot read |
| saved peer / direct peer | peer | the two kinds go in phase 4 |
| label, `LabelId`, `label.0` | sync ID, `SyncId`, a record name to pick (implementor) | |
| placed (spec/sync.md §5 **Placed**: a commit held under each of its labels at one of their hosts) | **held at a peer**; "uploaded" where only the upload is meant | not group membership: that word is **member** |
| person (actor) | account | issues/account-rename.md |
| edge | grant | issues/grant-rename-multi-actor.md |
| routing, routed (where an API call goes) | source | the sharing sense of "route" may also go, phase 2 |

The full registry stays issues/deprecated-terms.md. Renames come in phase 5, after the concepts they name are unified: renaming first would keep the two kinds of peer under new names.

## Model: actors, groups and sync IDs
**Today.** A group is what syncs, under a label (sync ID) with an index that rises only when a label is replaced. Label keys derive from the group's own secrets, so syncing a group first gives it secrets of its own, which makes it an actor. The first holder of a plain thing besides its first admin also gives it secrets of its own. An actor's home label is the actor synced as a group of itself, and its inbox is one of its labels. A grant records the permission and nothing else (spec/sync.md §2 "a grant makes none"; notes/api.md `grant`): a holder with no label carrying the thing has the role and reads nothing (`SyncState::NoRoute`) until someone calls `sync`.

**Direction (Tess: "maybe"; role and the ability to sync should be paired).** Proposed:
- Every actor with role secrets has exactly one live sync ID, its home. A group's sync ID, an actor's home and its inbox are the same thing.
- Making something an actor (a grant to a plain thing, `sync` of a group, `make_link`) gives it its sync ID in the same commit. A role on an actor is then always a role on something that syncs, so a grant always comes with a route. `NoRoute` goes.
- What travels under a sync ID stays as today: the actor's closure by membership (`group.0`) and entitlement (spec/sync.md §3). A plain thing in a shared group needs no sync ID of its own: it travels under the group's. A thing in two groups is one blob under both.
- "Nothing syncs by being created under an actor" (requirements) still holds: granting is an explicit act of sharing.

**Unsure:**
- (Tess) Whether to adopt this. It reverses "a grant records the permission and nothing else", and spec/sync.md §2 "a grant makes none".
- (design) Cost: a sync ID per granted thing means registration steps, node cards, heartbeats and a pass per sync ID (issues/idle-pass-per-label.md). Fine if per-sync-ID cost stays flat and small; measure before deciding. The pattern of sharing sets through one actor (notes/permissions.md Patterns) keeps counts low anyway.
- (design) What `sync(group)` still does: make a group an actor? only choose peers? Then `sync(thing)` for a single thing (today `make_link` makes one quietly) may need no call of its own.
- (design) Key actors (nodes, link keys, recovery keys) have no role secrets and no home. Today they reach labels from cards, links and static entries; check that this still covers them.
- (design) **Replacement (index > 0).** Its stated reason is a removed admin re-registering a label first at a host, with keys only it knows (notes/label-access.md, Replacement labels). Carriers that cannot read the data still hold registration state (a step head), so the race is still possible with any carrier, not only "hosts". Unclear whether it is worth its cost (an index, retiring, `register_path`, hints that name an index) once any node can carry and an admin can just rotate and step at the peers it reaches. Nobody has decided either way. Decide in phase 4, with the one serving path.

## Phases
Order matters: 0 makes the rest testable; 1 and 2 are small and remove the worst false reports; 3 makes first contact work on a LAN; 4 is the big unification; 5 renames; 6 hardens. 1-3 can partly overlap. The model change above fits best between 2 and 4 (unsure, design: it may be easier inside 4).

### 0. Tests that can fail (all rows)
- The sim's `World` drops every dial that isn't a hub (core/test/sim/src/world.rs `World` dial handling), so sims and sweeps never run peers: give it peer connections, NAT and partitions.
- `Transport::InProcess` dials any listener by key (core/transport/src/multi.rs): make `peer://` need a hint or a LAN route, as real P2P does.
- Done when: the audit's probes (pNN/qN, not committed) are rebuilt as tier-1 tests and fail for the rows still open. Keep them as the phase checklist.
- Unsure (implementor): how much of the LAN to model in process (announcements, source addresses, windows).

### 1. One idea of a group's sources (rows 13-18; no wire change)
- A group's sources are its saved peers plus its co-readers. States, `wait_synced`, the pre-sync, catching up for `set_role` and history `complete` all judge over both.
- `Synced`: a finished pass with each source reachable within the timeout. `Unsynced` only at the timeout. Served sessions count as connected. With nobody connected: not synced, shown as no peers, and a wait keeps waiting until its timeout (Tess).
- `wait_synced(Thing)` stops failing at once (row 16). `AllWithSavedPeers` becomes all groups.
- Unsure (design): what a `Required` wait promises when no single node holds every write. Proposed: a pass with the holder's own node if reachable, else any co-reader, else `Unsynced` at the timeout.

### 2. Mesh by default (rows 1, 3, 5, 10, 12, 22, 23, 24 in part)
- `lan` becomes non-optional in osis-transport, osis-node and osis, as QUIC and P2P are (a default on `osis` alone breaks the gate's unification check, notes/build.md).
- The CLI and app always run a runtime, saved peers or not (row 3).
- `reach.0` goes to everyone who shares a group, links included (today only where every reader is this account or a contact). Joiners then mesh, can dial either way, and hear LAN announcements.
- Rotate the dialable key only when someone is really removed. Then a grant, a second direct link or a link ending no longer cuts joiners off (row 10). A joiner stops depending on the key in the link text.
- Android: permissions (`ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`) and a held multicast lock over JNI; all unverified, needs a real phone (no-server-audit, Builds).
- IP privacy is out of scope here: any concern goes in issues/ip-privacy-settings.md (Tess).

### 3. First contact and delivery without an address (rows 6, 8, 9, 12, 21)
- **Links find the sharer on a LAN**: a LAN tag and sealed signature derived from the link's secret, announced while the link is open, so holding the link is what recognises the sharer.
- **Links carry current address hints** besides key and relays. spec/sync.md §10 "links and `label.0` list relays only" changes: a link is a bearer secret handed over out of band, and hints are what work on a routed mesh.
- **Contact cards** become direct links when there are no saved peers (row 8), so `import_contact` and names work.
- **Inbox over any connection**: an inbox may name `peer://` peers, dialed like any peer; the recipient's own node serves its inbox already. Until delivered, a grant stays pending and shows in status, never silently "sent" (row 9). Minimum first step: a grant to an inbox with no route reports it.
- A bundle may carry the K sync ID's entry box, so a link redeems by bundle alone (row 21; cause of today's timeout not traced).
- Unsure (design): how long a link announces on the LAN, and what it costs a sharer with many open links.

### 4. One kind of peer (rows 25-29)
Today a node has three serving paths, two stores and three listening keys:

| | Saved peer (old host) | Direct peer (co-reader) |
|---|---|---|
| Found by | fixed address in `label.0`, link and card text | `reach.0`, LAN, a link's sharer |
| Who can be one | a node with `set_serving` and `Admit` | a node that reads the group |
| Serving code | the hub (`osis-host`) | `sync/serve.rs` |
| Store | `host.redb` (blobs) | `db.redb` (plaintext state) |
| Key | serving key | dialable key (plus the client listener key) |

Steps, in the order of what they unblock:
1. **An address that names a node**: `peer://` allowed among a group's peers, dialed by key (spec/sync.md §10, spec/wire.md §10, conn.rs `peer://` skip; rows 26, 27).
2. **One listening key per node** (Tess): the dialable key, also its key as a carrier; dialers stay ephemeral. The client port keeps its own access rules on it (notes/client-port.md §5).
3. **One serving path**: the hub and co-reader serving become one, differing only in what proof opens a sync ID (spec/sync.md §4-§6; proof 3 is refused at hosts today). Hosts replicating to each other folds in or goes.
4. **One store**: a node carrying a group it also reads keeps it once, not in both `db.redb` and `host.redb`.
5. **Consent**: `Admit` defaults to the user's own nodes (Tess). Not phrased around servers. Widening (contacts, co-readers) later.
6. **Finding carriers**: a node carrying a group's data is listed in the group's data by key plus hints, as `reach.0` is; members learn it by syncing (Tess). Adding a carrier later works per group, also for a group under someone else's account (row 26).
7. Then the API: `add_peer` takes any node, `peers(g)` is one list, `sync(g, peers)` adds to it, `set_serving` is only limits, `Connected` goes, and `SyncId` leaves the public API (Tess: good). Serving admission by sync ID (`admitted: set<SyncId>`) needs a replacement (design: by group, resolved by the node that admits; or by grant).

Keep: the code that serves data a node cannot read cannot decrypt anything (`osis-host` has no engine or keys; `tools/policy.py` `host_blind`). That is a security boundary inside every node, not a kind of node; keep it through the merge.

Unsure:
- (design) Whether one serving path also means one *protocol* path, or a shared store with two session kinds.
- (design) Row 24 (C to A through B never relayed: C's chain certificates) is a small bug of its own; fix whenever.
- (design) Replacement (Model, above).
- (Tess) Whether hosting stays opt-in by `Serving` config (fine as a default) once "serving" is just "carrying for others".

### 5. Spec, then code, in the new words
- Rewrite the spec sections the concept changes touch, in the new words (spec/overview.md Conventions; spec/sync.md §2, §4-§6, §10; spec/wire.md §10; spec/permissions.md §3, §7; spec/data-model.md §9 `host.0^`; requirements' "a hiding host", "a host's word", an inbox's budget "at a host").
- Then mechanical renames, a crate at a time: about 5,000 uses each of host and label across core, cli, app, libs and spec. The harness follows the code (`World::add_host`, `NetHost`, `Opening.hosts`). `osis-proto`'s `ClientSession` (the dialing side, unrelated to API clients) and `ServingSession::port_only` get names that say so.
- Unsure (implementor): split into one branch per crate to keep merges small, or one sweep while nothing else is in flight.

### 6. Hardening
- **LAN rules** (rows 30-34, 36): drop the source-address check (tag and signature already decide); tag windows as wide as `MAX_DRIFT`; `SO_REUSEADDR` or a status for a failed bind; LAN tags over every known co-reader, the cap only on dials; extra announcement targets for routed meshes (`LanConfig` into `Config`); faster re-announce on a join.
- **Clock** (rows 34, 35): one peer can set a node's clock offset today (median over all connections, no cap), and a pulled clock can fail the node's own commits. Bound a peer's influence or require agreement from several sources, and never let it fail a node's own commit (requirement: a wrong local clock harms only that node's own writes).
- **Relays** (issues/p2p-own.md): co-readers as relays, relaying for strangers as a setting, port mapping later.
- **Recovery** (rows 2, 19): issues/recovery-redesign.md, Tess's call; its peer side (restore through peers and the LAN) depends on phase 4.
- Link expiry with no saved peer (row 37), co-reader cap (row 36).

## Side track: clients
Default policy (Tess): a unix socket opens without authentication as the node's main actor; a localhost or network listener lets a client act only as actors it has cryptographically authenticated for. To build: a credential names the actor it acts as. Today the transport decides (socket: main actor; secret: an actor minted for it). Unsure (Tess): whether "cryptographically authenticated" needs a signature by the actor's key rather than today's bearer secret inside TLS. Acting as several actors in one process: issues/grant-rename-multi-actor.md (`act_as`).

## Decided (Tess)
- One concept of node and of peer; "host" is deprecated, never built on.
- Synced = caught up with every node connected on the group; nobody connected is not synced.
- Who may store data on a node that it cannot read: by default only the user's own nodes.
- Carriers are listed in group data by key plus hints, learned by syncing.
- One listening key per node.
- Stores, serving paths and names: ours to decide.
- Unify the concepts before or with the rename, never rename first.
- Sync IDs leave the public API.
- IP consent: any positive action is consent (spec/sync.md §10). Relaying for co-readers by default, for strangers only when the user turns it on; no default relay in builds.
