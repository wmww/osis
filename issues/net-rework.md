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
- Each job lands with tier-1 tests that fail without it, over the transport and sim from issues/net-tests.md, never over `InProcess`'s find-anyone-by-key.
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
- Who may store data on a node that it cannot read: by default only the user's own nodes, which serve the user's groups with no setup; anyone else's is opt-in. A box run to store data unread is an ordinary node with no keys to it (issues/net-one-peer.md).
- Stores, serving paths, keys and names: ours to decide.
- Unify the concepts before or with the rename, never rename first.
- Sync IDs leave the public API; `unsync` goes; sync ID replacement (index > 0) goes (in job 8, where the serving path that made it necessary goes; it stays until then).
- Role and sync are paired, strong form (issues/net-role-sync.md); spec/requirements.md "add to synced groups" becomes "add to synced groups or share them".
- Two layers: connecting, then finding the shared sync IDs. On a LAN a node connects to every osis node, both exchange identity, and the shared set runs only with known actors (issues/net-connect.md). A node shows its identity only to nodes of actors it already knows (spec/requirements.md, Offline and network); a first build may break this on the LAN as a listed gap. Two accounts that don't know each other don't share directly, for now.
- `set_role` writes at once; an app catches up first with `wait_synced` (issues/revocation-without-arbiter.md).
- **No per-node data in groups**: a group names accounts, never its holders' nodes (issues/account-signing.md, which goes first). Off-LAN discovery of other accounts' nodes is not solved in this rework: better unsolved than built on per-group node data. The rework's end state holds on a LAN, through a reachable node and at known addresses.
- IP consent: any positive action is consent (spec/sync.md §10). Relaying for co-readers by default, for strangers only when the user turns it on; no default relay in builds. Privacy concerns go to issues/privacy.md.

## Jobs and order
Depends on issues/account-signing.md: what a connection proves (3, 5-6), the peer record (6) and what groups list (8) build on it. It needs no job here first.

1. issues/net-tests.md: tests that can fail. Its steps 1 and 5 (in-process P2P with routes, the audit's probes as ignored repro tests) come before every other job.
2. issues/net-honest-status.md step 1: one idea of a group's sources (the connections with it open, whoever dialed, `sources(L)` of issues/net-sync-structure.md) and the API: status and waits stop lying. Its step 2 (the served side judging by its own pull) lands with 6.
3. issues/net-connect.md: connect to every LAN node and recognise known actors privately, off the LAN only known addresses and own nodes, one stable listening key, LAN rules. The LAN route machinery goes here and not before (issues/net-sync-structure.md).
4. issues/net-role-sync.md: role and sync paired. Engine and spec work; can land before 8.
5. issues/net-shared-set.md and 6. issues/net-reconnect.md: one mechanism. One beacon filter per peer keyed by credentials' match values (read secrets, key actors' static entries, a served head's sync and deposit keys) plus role offers between known actors; deposits are offers to proved holders of the inbox; a durable per-peer record found by a pair key both nodes hold and one node-wide log, so a reconnect sends what changed and any node, however long away, catches up in one stream. A peer may recognise a device across connections (Tess; spec/requirements.md). `SyncEngine::proven` reads chain certificates from the connection's proof exchange, never from group data (issues/account-signing.md step 7 removes them there).
7. issues/net-first-contact.md: links, contact cards and grants work with no server, through 3 and 5.
8. issues/net-one-peer.md: one kind of peer: one key, one serving path, one store; sync IDs leave the API; replacement goes.
9. issues/net-rename.md: spec, then code, in the new words.

5-6 decide much of 2, 7 and 8 (what an open is, what a peer must know), so their design is settled first. 3 and 4 can run beside them. The LAN rules in 3 are independent. The structural refactors each job needs: issues/net-sync-structure.md. Related, owned elsewhere: issues/p2p-own.md (relays), issues/clock-peer-offset.md (a peer can pull a node's clock), issues/recovery-redesign.md (its peer side needs 8), issues/client-auth.md (client credentials), issues/privacy.md.

## Open (whole project)
- (design) The node's tick per sync ID (issues/idle-pass-per-label.md): the one per-sync-ID cost that still bounds the pairing and the shared set (issues/net-shared-set.md, Costs).
- (design) The private LAN recognition (issues/net-connect.md) and its cost per known actor.
