# Sharing through a tag is not one core operation
> Summary: Tag sharing (notes/tags.md) is built by each app from placements plus roster edges, so an app must grant on tag, grant recursively on nest, and work out, queue, retry and race revocations on untag itself; the app prototype did and it was its buggiest code (dropped since). Ask: tag, untag and nest as core operations that carry their access with them.
> Tags: core-ask, owner-call, permissions, api

Owner: flagged for review; decide the model before any app builds on it again.

What an app has to do today (the app prototype's former `add_tag`/`share_below`/revocation code, in git history before this issue):
- Tag: place, then `grant(t, tag, Write)` where I am admin; nest: `add_subgroup`, then grant every item and sub-tag below that I may share.
- Untag: unplace, then decide whether the tag's edge came from tagging and whether the tag still reaches the thing (sub-tags, cycles, diamonds, `member_path`), then `demote` asynchronously with a pre-sync, queue it durably for offline retry, back off, and drop it when moot.
- Placement and grant are separate commits on separate labels: a device that sees the placement but not the grant and untags queues nothing, and the later grant stands (thing shared after the user took it out; the app test showing it went with the app's sharing logic). A grant can also arrive after a removal it did not see.
- No provenance: an edge from tagging cannot be told from one granted by hand or by another admin, so untag may revoke the latter.
- `demote`'s "still reaches it another way" outcome is only in the error text (`Error::Invalid` containing "reaches").
- Someone removing my thing from their tag cannot revoke the tag's edge on my thing (they are not admin), so their tag keeps access.
- Order on a failed half: placing before granting leaves the thing tagged but unshared when the grant fails (a regrant after a revoke used to fail this way, fixed); granting first would leave a grant behind a failed placement. One causal unit (Ask) removes the choice.

Ask (directions, owner's call): `tag(t, tag)` / `untag(t, tag)` / nest as core calls whose access follows placement (an edge tied to its placement, or reach derived from placement under a shared tag), one commit or one causal unit so no device sees half; untag takes back exactly what tagging gave; typed outcomes; works offline or says clearly why not.
