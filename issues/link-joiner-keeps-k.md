# A link joiner keeps K after K is removed from the target
> Summary: When an admin removes a link's K from the target ("kick K, ending everyone behind it"), each joiner loses the target but still holds its role on K, so it syncs K's label for good and dials whoever reads it (the link's sharer, by the link follow and by `reach.0`): an idle session at the sharer per joiner, forever. Likely rule: a joiner leaves K once a held role history shows K's grant on the target removed or past `until`, the condition spec/permissions.md §7 already uses for "the link has ended".
> Priority: normal
> Tags: permissions, node-sync

- Repro: `repro_a_joiner_whose_link_was_removed_stops_dialing_the_sharer_spec_permissions_7` (core/test/sim/tests/it/no_server.rs).
- Not a dialing rule's fault: the joiner reads K, so every rule that dials for a synced label dials for it (notes/networking.md, First contact).
- Not a call for Tess: the permission model ends a hold on K only by a removal from K (K's admin) or the holder's own leave, and K's admin may be gone (notes/api.md: the target's admins then end the link by removing K). §7 already says the link has ended once K's grant on the target is removed; the joiner leaving K then (a self-removal, always allowed) extends that rule from the redeemer to the joiner. Cost: a target admin re-granting K no longer brings the joiners back (a new link does).
