# Grants carry the whole path, uncounted
> Summary: a static entry's grant (a Static item's accepted Hit, or a Behind item by a key actor naming no step) carries the path from genesis; Static Hits' grants are not counted against an Offer's step bound, and a path past about 29 000 steps fits no reply, so such a label's link redeemer is never answered.
> Priority: low
> Tags: sync

- **Cost.** Each accepted Static item reads the label's whole path (`unread_grant`, `ServedLabel::grant`); an Offer of 1024 of them by a live link holder reads 1024 paths. Behind answers share a per-Offer bound of `REPLY_BUDGET / MAX_STEP_BYTES` steps (notes/flow-control.md, Hub stall bounds), which a Static item's grant does not count against, and a Behind item's grant is read before it is charged (one path past the bound per Offer).
- **Size.** A path of more than about 29 000 steps (323 B each) passes `MAX_MESSAGE`: a Static Hit's Shared reply cannot be sent, a Behind item's grant is answered 4 for ever.
- To weigh: a grant carrying the path from a step the redeemer names, or the redeemer catching up by Behind items from there.
