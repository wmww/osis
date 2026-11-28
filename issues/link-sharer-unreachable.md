# A link names its sharer with no address
> Summary: A link lists its sharer as `peer://#KEY` with no item (the product has no relays to list), so a redeemer reaches the sharer only over a LAN; with no configured node of the sharer's that holds K, `chat join LINK` and `link redeem` fail ("could not confirm this link yet") while the sharer is up. spec/sync-transport.md §3 says both "one URL in dial entries and links" and "a link lists relays only".
> Priority: normal
> Tags: sync, osis, cli, tess-call

Seen in the dogfood smoke pass: A, B, C chat peer to peer on loopback, each daemon `--dial`ing the others. A's `chat link` lists A as `peer://#<A's key>` (empty), then B and C (A's configured addresses). D's `chat join` dials all three: A fails at once (`unreachable: peer://`), B and C answer Head for K's sync ID with Error 13 (they hold the chat, not K), and D gives up. With `--dial <A's address>` it joins. The dogfood channel works only because its shared node is every member's configured address and keeps K unread (notes/dogfood.md).
- `Osis::link_peers` passes no relays (there is no relay setting), so the sharer's URL is always empty; A's own dial entry (`dial.0`, `publish_reach`) meanwhile lists `peer://[<global IPv6>]:<port>`.
- spec/sync-transport.md §3 contradicts itself: "Its URLs, in those entries and in a link's peers (spec/wire.md §10), are one: its `peer://` URL" against "A link lists its sharer node's relays only, never the node's socket addresses" (spec/wire.md §10 says the latter).
- The sync harness builds links with the node's public addresses and relays (`World::make_link`, `World::locator`: `reach.items`), so its tests redeem links the product never makes.
- A one-shot `chat join`/`link redeem` runs with `Lan::Off`, so even on one LAN it never finds a sharer known by key alone.
- Decision: list the sharer's `peer://` URL (its global addresses and relays, as `dial.0`), which reveals its addresses to whoever holds the link, or keep relays only and make a relay (or a node keeping K unread) part of making a link. Either way the harness should build links as the product does.
