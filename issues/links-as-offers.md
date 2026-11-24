# Share links and offers are one idea in two formats
> Summary: Follow-up to the reference graph (Tess). An offer (a `grant@~0` fire, spec/sync-inbox.md §5: the thing, its sync ID and the holder's boxes, sealed to the holder's inbox) and a share link (spec/permissions.md §7: text carrying a thing's ID, sync ID, a bearer secret and peers to dial) both say "here is how to start syncing this". To study: one bootstrap format, sealed to a thing (an offer) or open (a bearer link), with the link text as that value written out.
> Priority: low
> Tags: sync, permissions, data-model

- Study after A5: an offer is a bootstrap only (notes/holder-access-study.md, The direction: nothing after it depends on it), and cards are redesigned there (notes/write-path-design.md §3, The card). Until then links stay as they are.
- To read before designing: the link's key actor K and its roster, redeem and join, finalize, bearer use (read only), first contact by the link's peers (spec/permissions.md §7, spec/sync-inbox.md §6); notes/stubs.md (a reference carries no way in: an offer or a unit does).
- Differences a merge must keep or drop on purpose: a link carries addresses (a first contact has nothing else to dial; an offer carries none); a link's holders join through a thing with its own roster, K (an offer's holder is the thing it is sealed to); a link can be ended by removing K; an offer is kept the inbox lifetime and proves nothing.
