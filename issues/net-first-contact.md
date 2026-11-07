# First contact and delivery without a server
> Summary: Links, contact cards and grants assume a saved peer (audit rows 5, 6, 8, 9, 12, 21, 37). Design: once connected (issues/net-connect.md), a link's holder finds K's sync ID like any other (issues/net-shared-set.md, matched by the link key's static entry), and a grant is deposited at any connected node serving the recipient's sync ID (matched by deposit key). No `direct` links; a card is a plain link; undelivered grants show as pending. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, api, node

## Today
- Link text: L's seed, target, K, K's label ID and hosts, and with `direct` the sharer node's dialable key and relays (spec/wire.md §10). A redeemer reaches K's label only at a listed host or by dialing that key. On a LAN it cannot: a `peer://` key with no relay gives nothing to dial, and LAN tags match co-readers only (row 6). Not direct with no saved peer: `Invalid` (row 5).
- A contact card is a link that is never direct, so it is `Invalid` with no saved peer: no `import_contact`, no names, chat's `link` and `add` fail (rows 8, 12).
- A grant to a known account with no saved peer: the deposit loop runs zero times and marks it sent (row 9).
- Redeem by bundle alone times out (row 21). The format already carries claim sets with their entry boxes (spec/wire.md §8, §12), so the cause is elsewhere; not traced.
- With no host only the node that wrote the seed thing finalizes an ended link (row 37; spec/permissions.md §7 Finalized).

## Design
Connecting is issues/net-connect.md's; what two connected nodes open is issues/net-shared-set.md's. First contact adds no path of its own: it only needs those two to cover a link key and a depositor.
- **Links.** The redeemer holds L's seed, a bearer secret of K: after the handshake it proves L (a known actor to every node administering K's roster, issues/net-connect.md) and sends a secret beacon keyed by L's seed (issues/net-shared-set.md), which any node serving K can test: the sharer's nodes, joiners. The match opens K; K's grant gives the target. A peer that cannot read K opens it by static entry claim as today (spec/wire.md §8). Recovery cards find their home the same way (issues/recovery-redesign.md).
- **Link text**: L's seed, target, K, K's sync ID, and connect hints (key and addresses of nodes serving K, the maker's to begin with). No hosts, no `direct`, no `LinkOpts.direct`. A redeemer connected some other way (LAN, a common node) finds K all the same; a node a held link names counts as one its holder may connect to (issues/net-connect.md's trust setting). `make_link` works on every node, runtime or not (row 5).
- **Contact cards**: a plain link (read on the profile), so they work when links do (rows 8, 12).
- **Grants** (row 9). The inbox is the recipient's sync ID (issues/net-role-sync.md), which its `keys.0` names with the deposit seed. The sender derives the deposit key and deposits at every connected node serving that sync ID, matched by deposit key. Those are usually nodes it already syncs with: it learned the `keys.0` through a shared group or the recipient's card, which the recipient's nodes serve. Until a node takes it the delivery is pending in status and waits, never "sent". First step, before shared-set lands: report a delivery that has nowhere to go (issues/net-honest-status.md).
- **Inbox payloads** name sync IDs only, no hosts (spec/wire.md §9, spec/sync.md §3 Following a payload label).
- **Bundles**: a link redeems from a bundle alone (row 21); trace why it does not.
- **Link expiry** (row 37): any sharer node holding the seed thing and admin on K finalizes after a complete pass with its connected sources (issues/net-honest-status.md). A redemption it has not seen is dropped by the removal's frontier, as now (spec/permissions.md §7).

## Unsure
- (design) Peers that cannot read: a link holder opens K there by static entry; check it needs nothing more once hosts go (issues/net-one-peer.md).
- (Tess, via issues/privacy.md) Whether links and cards carry connect hints by default: hints give an address to everyone holding the text, and a card is shared widely. Without them a holder needs another connection to a node serving K.
- (design) A grant to an account whose nodes the sender never connects to (it learned the `keys.0` through a group the recipient left): proposed, it stays pending, shown. Carrying deposits for others is relaying (issues/p2p-own.md).
- (design) Row 37 above: whether finalizing at more than one sharer node needs any order (two explicit removals of L).
