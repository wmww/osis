# Grants carry the whole path, uncounted
> Summary: a static entry's grant (a Static item's accepted Hit, or a Behind item by a key actor naming no step, spec/sync-ids.md §6 Behind) carries the path from genesis; Static Hits' grants are not counted against an Offer's step bound (`MAX_BEHIND_STEPS`), and a path past about 29 000 steps fits no reply, so such a sync ID's link redeemer is never answered.
> Priority: low
> Tags: sync

- **Cost.** Each accepted Static item reads S's whole path (core/sync/src/opens/holds.rs `grant`, `Store::path`); an Offer of `MAX_ITEM_HITS` of them by a live link holder reads that many paths. Behind answers share a per-Offer bound of `MAX_BEHIND_STEPS` (`REPLY_BUDGET / MAX_STEP_WIRE`), which a Static item's grant does not count against (`Store::behind`).
- **Size.** A path of more than about 29 000 steps (326 B each in a message) passes `MAX_MESSAGE`: a Static Hit's Shared reply cannot be sent, a Behind item's grant is answered 4 for ever.
- To weigh: a grant carrying the path from a step the redeemer names, or the redeemer catching up by Behind items from there.
