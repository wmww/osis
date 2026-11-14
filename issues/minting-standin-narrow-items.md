# A purge item by commit or author ends a kept minting copy but not the dropped one
> Summary: `Minting::stands_in_for` drops a lower minting copy under S below one whose purge rights are contained in its own, but a request naming the kept minting by commit (or by author, actors differing) ends it alone, so a node holding only the kept copy and the request judges t destroyed while it is live elsewhere.
> Priority: low
> Tags: security, engine, sync

- Case: t's minting D (`author_or_admin`, actor A, expiring at E) and K (`author_or_admin`, actor A, durable): K stands in for D, so D's copy leaves S. A purges K alone by a `[tid, created.0, ts, source]` item (`purge::reaches`: a commit item reaches one minting whatever its stamp). A node joining S later holds K and the request only: it judges t destroyed at the request, before E, and past the window for good, while holders of D read t live. Same with an item by author when K's and D's actors differ (any class).
- Heals within the window wherever a holder of D is online in S (D becomes its witness and is logged again). Only a holder of the right over both mintings can cause it.
- spec/commits.md §5 says "a purge item on `created.0` names every minting of its thing, whatever its `ts`", spec/wire.md §4 and the engine let a commit or author item name one. Fix options (spec first, then `purge::reaches`): every item on `created.0` names every minting (or only `[tid, created.0]` items are valid there); or a lower copy goes only below a kept one no item can end alone (none: drop the drop rule).
