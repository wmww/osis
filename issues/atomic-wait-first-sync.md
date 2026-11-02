# A node's first sync of a thing applies commits without waiting for their other bodies
> Summary: Atomic apply waits only for things in `ix.syncing`, and `sync_closure` adds a thing only at a pass after its creation record is held. So commits arriving with the thing, or before that pass, apply at once with their other bodies missing, whatever their retention. Spec/commits.md §4 says a node waits for what it syncs. They join late if the body comes, and a body hidden by a host leaves the commit half applied for good.
> Tags: engine, sync, spec

Repro: reader in the group, offline. Writer writes c1 = {`t:gone.0` under another retention class, `t:reg.0`}, so two blobs. `net.hide_blobs` hides the `gone` blob from the reader, which comes online for the first time. Result: `reg` reads c1's value, `gone` reads nothing, nothing pends. The same reader, once already syncing the thing, waits.

Fix sketch: treat an unknown thing under a synced label as synced (commit examined against the label it came under), or hold a label's first batch until the closure is walked. Either way the wait then costs a first sync its re-examination (notes/node.md, Re-examination).

Tests that want the wait must `set_syncing` before delivering (`order::carrierless_*` do; the rest of the `order::` harness's fresh nodes never sync, so its late-part modes never exercise the wait).

Parts waiting alone (spec/commits.md §4) did not fix this and widen it slightly: at a first sync, before the closure walk, an honest commit on two things whose second record is not held now shows its first part in either arrival order, where before one order held it whole. It heals when the record comes. The fix sketch stands: once an unknown thing under a synced label counts as synced, that commit waits whole again.
