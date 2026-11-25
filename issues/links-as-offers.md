# Share links and offers are one idea in two formats
> Summary: An offer (a `grant@~0` fire, spec/sync-inbox.md §5: the thing, its sync ID and the holder's boxes, sealed to the holder's inbox) and a share link (spec/permissions.md §7: text carrying a thing's ID, sync ID, a bearer secret and peers to dial) both say "here is how to start syncing this". To study (Tess): one bootstrap format, sealed to a thing (an offer) or open (a bearer link), the link text that value written out.
> Priority: low
> Tags: sync, perm, data-model

- An offer is a bootstrap only (notes/holder-access-study.md, The direction). Pairing already hands an offer over its channel (notes/accounts-switch-brief.md).
- Differences a merge keeps or drops on purpose: a link carries addresses (a first contact has nothing else to dial; an offer carries none); a link's holders join through its link key L, a thing with its own roster (an offer's holder is the thing it is sealed to); a link ends by removing L; an offer is kept the inbox lifetime and proves nothing.
