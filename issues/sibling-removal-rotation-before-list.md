# A sibling taking a removal's rotation before its D list leaves its account
> Summary: at a node of P, a rotation carrying a removal from D decides on D at once (spec/permissions.md §5.5 Waiting), so a sibling not removed that holds it before its thing list for D (from a Prove's rotations, or a header-only copy under another sync ID) reads D's roster as P alone and leaves for good (`signing::leave`).
> Priority: normal
> Tags: engine, sync

- Why the carve-out: a removed node gets neither its removal nor D's later lists from its siblings (they serve D only to D's roster), so reading D's roster as P alone is how it learns it was removed (osis-sync `duties::a_node_removed_from_its_account_stops_syncing_*`). A sibling and the removed node hold the same thing at that moment; only what arrives later tells them apart.
- The spec's own tool for that is the leaving pass (spec/sync-set.md §3: keep syncing S through a complete pass, "what that pass brings may give S back, as a rotation's thing lists arriving after the rotation do"), but `leave` drops the account's seeds at once and for good, and with D's roster read as P alone no sibling is a peer to wait for. Fix shapes, both engine: a removed node is shown its removal (its siblings log the removal to it, wrapped under the pre-removal D epoch), then Waiting can hold for every closer; or leaving waits for that pass.
- Shape to test: siblings 1, 2, 3; node 1 removes node 3; node 2 takes the rotation from node 1's Prove before home brings the removal and the list.
