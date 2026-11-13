# Networking rework
> Summary: Hub of the networking and sharing rework: the end state, the target words, rules for every job, what is decided, the order, and the index of job issues (`net-*`). Evidence: issues/no-server-audit.md. Scope, structure and Tess's calls are settled; what is open is design work inside the jobs.
> Priority: normal
> Tags: node, sync, transport, api, spec

The networking and sharing layer grew around a server ("host") and had P2P added beside it, and much of it was never designed as a whole. This issue owns the order; each job issue owns its own design and open points. Requirements: spec/requirements.md, Decentralization and Offline and network. Audit rows (`row N`) are issues/no-server-audit.md's.

## End state
- One concept of a node and one of a peer: any node a group syncs with, whether or not it can read the data. "Host" is gone from spec, code and notes.
- Every feature works with no server, relay or internet: on a LAN, on a dynamic mesh, through any willing node.
- Holding a role is what lets a node sync the thing (issues/net-role-sync.md).
- Two connected nodes of accounts that know each other find the sync IDs they share without prior knowledge of each other's nodes, and a reconnect costs about what changed.
- Status and waits say only what is true; nothing reports a delivery that did not happen.
- Spec and code use the current words; sync IDs are not in the public API.

## Rules for every job
- Clean, simple, general. A mechanism that handles only most cases (and so needs special cases or breaks) is rejected, however cheap (Tess).
- Each job lands with default tests that fail without it, over the transport and sim from issues/net-tests.md, never over `InProcess`'s find-anyone-by-key.
- Each picked number passes notes/arbitrary-values.md; each public API change passes notes/api-design.md.
- IP privacy is out of scope: any concern goes to issues/privacy.md (Tess).
- **Reachable through anything** (Tess): a job must not make it impossible for two nodes to sync through a node between them, over any carrier, the node between not being in the group (issues/net-mesh-discovery.md). Above the connection layer nothing assumes a peer is directly reachable, is on IP, was found by broadcast, or that a node passing data reads it. So the connection layer must be encrypted end to end through any node between (spec/sync.md §10 requires confidentiality and an authenticated peer key of the stream, a requirement on the two ends, not on a hop): the pair key r, challenges and every Hit reach only the other end. Nothing here is built for it yet.
- **Unsure** in the job issues marks what is open: (Tess) her call, (design) to settle when the job starts, (implementor) settle in the code.

## Words (target)
| Old | New | Notes |
|---|---|---|
| host, hosts, hosting, carrier | peer; a node **serves** a group | no word for a peer holding a group it cannot read (Tess): "a peer that cannot read it" where it matters. "Carrier" is also taken: retention's body holding a live write |
| saved peer / direct peer | peer | the two kinds go in issues/net-one-peer.md |
| label, `LabelId`, `label.0` | sync ID, `SyncId`, a record name to pick | |
| placed (spec/sync.md §5 **Placed**: a commit held under each of its labels at one of their hosts) | **held at a peer**; "uploaded" where only the upload is meant | not group membership: that word is **member** |
| person (actor) | account | issues/account-rename.md |
| edge | grant | issues/grant-rename-multi-actor.md |
| routing, routed (where an API call goes) | source | |

The registry of old words stays issues/deprecated-terms.md. Renames come after the concepts they name are unified (issues/net-rename.md): renaming first would keep the two kinds of peer under new names.

## Decided (Tess)
- One concept of node and of peer; "host" is deprecated, never built on. No separate word for a peer that cannot read a group. The values two nodes compare to find shared sync IDs are **beacons**, not tags (a tag is a group shown to users).
- Synced = caught up with every node connected on the group; nobody connected is one state, not synced.
- Who may store data on a node that it cannot read: a node holds exactly the sync IDs under its synced group, which its account writes; one it cannot read it holds by a sync-only grant, accepted like any grant. Keeping data unread takes no other kind of node: readability is per (node, sync ID) (issues/net-one-peer.md, Sync model).
- Stores, serving paths, keys and names: ours to decide.
- Unify the concepts before or with the rename, never rename first.
- Sync IDs leave the public API; `unsync` goes.
- Role and sync are paired, strong form (issues/net-role-sync.md); spec/requirements.md "add to synced groups" becomes "add to synced groups or share them".
- Two layers: connecting, then finding the shared sync IDs. On a LAN a node connects to every osis node, both exchange identity, and the shared set runs only with known actors (issues/net-connect.md). A node shows its identity only to nodes of actors it already knows (spec/requirements.md, Offline and network); a first build may break this on the LAN as a listed gap. Two accounts that don't know each other don't share directly, for now.
- `set_role` writes at once; an app catches up first with `wait_synced` (notes/api.md, Demotion and addenda).
- **No per-node data in groups**: a group names accounts, never its holders' nodes (issues/account-signing.md, which goes first). Off-LAN discovery of other accounts' nodes is not solved in this rework: better unsolved than built on per-group node data. The rework's end state holds on a LAN, through a reachable node and at known addresses.
- IP consent: any positive action is consent (spec/sync.md §10). Relaying for co-readers by default, for strangers only when the user turns it on; no default relay in builds. Privacy concerns go to issues/privacy.md.

## Jobs and order
Depends on issues/account-signing.md: what a connection proves, the peer record and what groups list build on it.

Built, leftovers in each issue: issues/net-tests.md (the harness), issues/net-honest-status.md (status and waits judge `sources`), issues/net-role-sync.md (role and sync paired), issues/net-shared-set.md and issues/net-reconnect.md (one mechanism: a beacon filter per peer, role offers, deposits as offers, a durable per-peer record found by a pair key, one node-wide log and stream; `SyncEngine::proven` reads only the connection's proof exchange). Open, in order:
1. issues/net-connect.md: connect to every LAN node and recognise known actors privately; off the LAN only known addresses and own nodes; one stable listening key; LAN rules. The LAN route machinery goes here (issues/net-sync-structure.md (c)).
2. issues/net-first-contact.md: links, contact cards and grants work with no server, through net-connect and the shared set.
3. issues/net-one-peer.md: one kind of peer (one key, one serving path, one store); sync IDs leave the API; replacement goes. Carries issues/net-shared-set.md step 9.
4. issues/net-rename.md: spec, then code, in the new words.

The structural refactors each job needs: issues/net-sync-structure.md. Related, owned elsewhere: issues/p2p-own.md (relays), issues/recovery-redesign.md (its peer side needs net-one-peer), issues/client-auth.md (client credentials), issues/privacy.md.

## Open (whole project)
- (design) The node's tick per sync ID (issues/idle-pass-per-label.md): the one per-sync-ID cost that still bounds the pairing and the shared set (issues/net-shared-set.md, Costs).
- (design) The private LAN recognition (issues/net-connect.md) and its cost per known actor.
