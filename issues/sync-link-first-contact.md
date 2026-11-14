# A link's first contact opens nothing
> Summary: redeeming a link (a contact card included) dials the sharer node and connects, but neither side syncs K's sync ID, so the join never happens; the differential still exchanges contacts by hand (`history::introduce`) until this works.
> Priority: normal
> Tags: sync, tests

- Seen in the sync harness: node 0 makes a read link to its profile (`Engine::create_link`, its dialable key and a relay as the peer hint), node 1 `Node::redeem`s it: node 1 dials node 0 by the link's hint (`Inbox::dial_hints`, a dial candidate) and the connection comes up through the relay; then `sync_holding(K's sync ID)` is `None` at both nodes, no member opens, and node 1 never gains the role.
- Missing: K's sync ID in the redeemer's sync set while it redeems (spec/sync-set.md §2: "a link's sync ID is followed as its redeemer redeems it") and in the sharer's (K is in no synced group's closure; osis `make_link` files only the seed thing in home).
- The account's own profile is in no synced group's closure (`create_account` and osis `create` file nothing; the harness's `introduce` files it in D), so a node's `dial^.0` entry (`Engine::publish_reach`) reaches neither its other nodes nor, before a card works, its contacts: no spec rule says the profile is listed. Simplest reading: the account's creation lists the profile in D.
- A link lists relays only (spec/wire.md §10), so a sharer with no relay is reached by a link only over a LAN.
- Done when `history::introduce` is replaced by contact cards: each node imports the others' cards (redeem, then the profile accepted, spec/sync-set.md §4).
