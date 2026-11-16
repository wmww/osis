# A timed loss whose write reached every peer keeps until the bound
> Summary: after a loss by an `until` alone, a node whose own write every peer holds can keep the thing until `LOST_HEARD_WAIT_MS`: no held report marks its commit elsewhere and not every waited peer refuses.
> Priority: normal
> Tags: sync, permissions

Repro: `life::a_refusal_by_one_node_ends_no_wait_on_its_sibling_spec_permissions_2`, extended after `heal(); run()` with `assert!(!holds(&mut w, 3, &t))`: it fails. Node 3 wrote y cut off, its `until` passed (node 0 finalized first, clock ahead), then everything heals and every node holds y. At node 3 `lost_passed` is true and one peer refuses, yet `Hears::timed_heard` stays false. A four-node variant (two readers of one account, the writer of a third) showed `Status::sourced(S)` true, no refuser, and the own commit's entry with `Store::elsewhere` false: no held report reached the writer.

Likely: peers that learned the finalize judge node 3 departed and send it no held report (spec/permissions.md §2 Meanwhile: they share nothing), yet keep S open there or close it with a Lost on a connection that stays up, which is no refusal (no fresh ByRole on it). Not data loss (the write is held), a stall to the bound in a plausible order. To settle: whether a close for J departed should count as a refusal (spec §2 A peer refuses it), or such a peer's holding should reach the node another way.
