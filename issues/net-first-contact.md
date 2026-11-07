# First contact and delivery without a server
> Summary: Links, contact cards and grants assume a saved peer: a direct link cannot find its sharer on a LAN, a contact card is `Invalid`, a grant to a known account reports sent and never arrives (audit rows 6, 8, 9, 12, 21). Make each work with no server, and make undelivered grants show. Depends on issues/net-connect.md and issues/net-shared-set.md. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, api, node

- **Links find the sharer**: the link is a bearer secret handed over out of band, so holding it can be what recognises the sharer (on the LAN, at a meeting point). Links also carry current address hints besides key and relays; spec/sync.md §10 "links and `label.0` list relays only" changes (row 6).
- **Contact cards** work with no saved peer (row 8), so `import_contact` and names work; chat's `link`, `add` and names follow (row 12).
- **Grants arrive** (row 9): delivery to an actor's inbox (its sync ID, issues/net-role-sync.md) over any connection to a node serving it. Until delivered it stays pending and shows in status, never "sent". Minimum first step: a grant with no route to the inbox reports it.
- **Bundles** carry what a first contact needs (the link key's entry box), so a link redeems by bundle alone (row 21; cause of today's timeout not traced).
- Link expiry when the maker is gone (row 37: only the node that made the link finalizes it).

Unsure:
- (design) How a link's holder recognises the sharer once connecting no longer depends on knowing nodes (issues/net-connect.md): perhaps the link's sync ID simply goes through issues/net-shared-set.md, since the redeemer holds its keys.
- (design) How a sender finds a recipient's nodes for an inbox it cannot read (issues/net-shared-set.md, Deposits).
- (design) Contact card as a direct link, or a card that names a sync ID found like any other.
