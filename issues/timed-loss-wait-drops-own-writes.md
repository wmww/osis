# A loss by an `until` drops unsent own writes at its wait's end
> Summary: past `LOST_HEARD_WAIT_MS` a node that lost read by an `until` alone drops its own writes from before the `until` held nowhere else; a user whose share was renewed while the device was offline that long loses them.
> Priority: low
> Tags: sync, permissions

spec/permissions.md §2: a sync ID of the lost actor is heard out only by evidence (own commits held elsewhere and a complete pass after the loss with a source, or no peer to wait for but those refusing it); a refusal ends the wait on its peer alone. So before the bound an own write held nowhere else goes only when every peer that may take it refuses it. At the bound (`ROLE_KEEP`, 90 days) the node drops anyway, writes included.

Who loses: a device offline (or reaching only peers that refuse) for 90 days past its `until`, whose writes made before the `until` were never sent, while some peer would still take them: one that holds a renewal of the grant the device has not heard, or a reader that files S later. A user expects those writes kept: they were made with access. Without a renewal every peer judging the device departed refuses them anyway (spec §2, Meanwhile), so the bound loses nothing more there.

Fix if convenient: keep own commits held nowhere else through the drop (their entries are wrapped already; the node would keep them as kept-unread entries to push to a peer that opens S later), so the drop erases what it read and nothing it wrote.
