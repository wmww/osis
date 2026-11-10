# A link joiner keeps K after K is removed from the target
> Summary: When an admin removes a link's K from the target ("kick K, ending everyone behind it"), each joiner loses the target but still holds its role on K, so it syncs K's label for good and dials whoever reads it (the link's sharer, by the link follow and by `reach.0`): an idle session at the sharer per joiner, forever. Decide what ends a joiner's hold on a K that reaches nothing (the sharer removing K's holders, a joiner leaving K once K's grant on its target ends, or a stated limit).
> Priority: normal
> Tags: permissions, node-sync

- Repro: `repro_a_joiner_whose_link_was_removed_stops_dialing_the_sharer_spec_permissions_7` (core/test/sim/tests/it/no_server.rs).
- Not a dialing rule's fault: the joiner reads K, so every rule that dials for a synced label dials for it (notes/networking.md, First contact).
