# Share links and tickets are one idea in two formats
> Summary: Follow-up to the reference graph (Tess). A ticket (spec/data-model.md §8: a weak carrying a thing's sync ID and a key sealed to a named thing) and a share link (spec/permissions.md §7: text carrying a thing's ID, sync ID, a bearer secret and peers to dial) both say "here is how to sync this". To study: one format, sealed to a thing (ticket) or open (bearer link), with the link text as that value written out.
> Priority: low
> Tags: sync, permissions, data-model

- Until then links stay as they are, and the ticket is designed so a bearer form fits later.
- The one place they meet in the plan itself: a contact card (a link, spec/sync-inbox.md §5) also gives post on the account's inbox thing. That changes what a card's link is granted, not how links work.
- To read before designing: the link's key actor K and its roster, redeem and join, finalize, bearer use (read only), first contact by the link's peers (spec/permissions.md §7, spec/sync-inbox.md §6).
- Differences a merge must keep or drop on purpose: a link carries addresses (a first contact has nothing else to dial; a ticket carries none); a link's holders join through a thing with its own roster, K (a ticket's holder is the thing it is sealed to); a link can be ended by removing K.
