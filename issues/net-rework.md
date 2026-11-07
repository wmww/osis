# Networking rework
> Summary: Hub of the networking and sharing rework: the end state, the target words, rules for every job, what is decided, the order, and the index of job issues (`net-*`). Evidence: issues/no-server-audit.md. Scope and structure are settled; many jobs still need design talks with Tess.
> Priority: normal
> Tags: node, sync, transport, api, spec, tess-call

The networking and sharing layer grew around a server ("host") and had P2P added beside it, and much of it was never designed as a whole. This issue owns the order; each job issue owns its own design and open points. Requirements: spec/requirements.md, Decentralization and Offline and network. Audit rows (`row N`) are issues/no-server-audit.md's.

## End state
- One concept of a node and one of a peer: any node a group syncs with, whether or not it can read the data. "Host" is gone from spec, code and notes.
- Every feature works with no server, relay or internet: on a LAN, on a dynamic mesh, through any willing node.
- Holding a role is what lets a node sync the thing (issues/net-role-sync.md).
- Two connected nodes find the sync IDs they share without prior knowledge of each other, and a reconnect costs about what changed.
- Status and waits say only what is true; nothing reports a delivery that did not happen.
- Spec and code use the current words; sync IDs are not in the public API.

## Rules for every job
- Clean, simple, general. A mechanism that handles only most cases (and so needs special cases or breaks) is rejected, however cheap (Tess).
- Each job lands with tier-1 tests that fail without it, over the transport and sim from issues/net-tests.md, never over `InProcess`'s find-anyone-by-key.
- Each picked number passes notes/arbitrary-values.md; each public API change passes notes/api-design.md.
- IP privacy is out of scope: any concern goes to issues/ip-privacy-settings.md (Tess).
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
- One concept of node and of peer; "host" is deprecated, never built on. No separate word for a peer that cannot read a group.
- Synced = caught up with every node connected on the group; nobody connected is not synced.
- Who may store data on a node that it cannot read: by default only the user's own nodes.
- Peers that cannot read a group are listed in its data by key plus hints, learned by syncing.
- One listening key per node.
- Stores, serving paths and names: ours to decide.
- Unify the concepts before or with the rename, never rename first.
- Sync IDs leave the public API.
- Role and sync are paired, strong form (issues/net-role-sync.md).
- Two layers: connecting (which nodes to connect to) and then finding the shared sync IDs. Connecting is the easier one.
- IP consent: any positive action is consent (spec/sync.md §10). Relaying for co-readers by default, for strangers only when the user turns it on; no default relay in builds.

## Jobs and order
1. issues/net-tests.md: tests that can fail. First: everything else is checked with it.
2. issues/net-honest-status.md: one idea of a group's sources; status and waits stop lying. Small, no wire change.
3. issues/net-connect.md: which nodes connect (LAN on, runtime always, mesh by default, who to trust) and the lower network layer (LAN rules, relays).
4. issues/net-role-sync.md: role and sync paired.
5. issues/net-shared-set.md: two connected nodes find the sync IDs they share.
6. issues/net-reconnect.md: reconnects cost what changed. Designed with 5: it may avoid redoing 5 on every connection.
7. issues/net-first-contact.md: links, contact cards and grants work with no server.
8. issues/net-one-peer.md: one kind of peer: one key, one serving path, one store; sync IDs leave the API.
9. issues/net-rename.md: spec, then code, in the new words.
10. issues/net-clock.md: a peer's clock cannot pull a node's.

2 and 3 can run beside 4-6. 5 and 6 decide much of 7 and 8 (what an open is, what a peer must know), so their designs come first. 10 and the LAN rules in 3 are independent and can go any time. Related, owned elsewhere: issues/p2p-own.md (relays), issues/recovery-redesign.md (its peer side needs 8), issues/client-auth.md (client credentials).

## Open (whole project)
- (Tess) Which jobs to design together in one session (5 and 6 at least).
- (design) Whether the per-sync-ID cost (registration, node cards, heartbeats, a pass each) stays small enough for the pairing (issues/net-role-sync.md) and the shared-set step; measure early, it bounds several designs.
