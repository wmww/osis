# revoke_link says done for a link whose seed has not reached this node
> Summary: `Osis::revoke_link` returns Ok for an ended link (its seed thing went with its end), judged by K's record alone; a node of the sharer that holds K's record (seen through K's grant on the target) before the seed thing (another commit, under D) takes a still-working link for ended and returns Ok without revoking it.
> Priority: low
> Tags: osis, security

- Reach: the caller needs the LinkId from another node (`links()` here does not list a link without its seed). Before the seed went with the link's end, an unknown seed was `Invalid`.
- Wanted: "ended" judged from something that says the link no longer works (L's grant gone from K, or a record of the end), not from the seed's absence; or `Invalid` ("not here yet") while K still has a live may-grant grant.
