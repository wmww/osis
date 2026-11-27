# The wait after losing read by an `until`
> Summary: After a loss by an `until` alone (spec/permissions.md §2) a node keeps the sync ID until it is heard out or `LOST_HEARD_WAIT_MS` (`ROLE_KEEP`) passes. At the bound the node drops its own writes from before the `until` that are held nowhere else.
> Priority: low
> Tags: sync, perm

- **Own writes lost at the bound.** A node offline for `ROLE_KEEP` past its `until`, whose writes from before the `until` were never sent, loses them while some peer would still take them (one holding a renewal the node has not heard). Without a renewal every peer refuses them anyway (spec §2, Meanwhile). Fix if convenient: keep own commits held nowhere else through the drop as kept-unread entries to push to a peer that opens S later, so the drop erases what the node read and nothing it wrote.
