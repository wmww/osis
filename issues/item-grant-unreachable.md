# A grant on a plain item alone reaches nothing
> Summary: `grant(item, holder)` or `make_link(item, ..)` to someone who shares no label with the item gives its secrets but no label to read it under: reads stay empty, `redeem` never resolves, nothing says why.
> Tags: node-sync, osis

An item's blobs travel under the labels of the groups holding it (spec/sync.md Entitlement), and those labels open under the group's secrets, which the grantee does not get. The inbox payload names only the thing's own label (spec/wire.md §9). Before that it named a group's label, which the item's secrets could not open either: same outcome.

What works: the item in a tag or group the grantee holds (notes/tags.md). notes/api.md `grant` does not say so.

Needs an owner choice: refuse or warn at `grant`/`make_link` on a thing with no label the holder can reach, or give the thing a label of its own on its first holder.
