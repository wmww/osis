# Held ephemeral state does not reach a label a thing enters later
> Summary: a thing already synced under one label, placed under a second, gives that label's readers only later writes; a node on two labels can miss the same way after a restart. Readers differ until a snapshot happens to cover it.
> Tags: ephemeral, node-sync

Commits are placed once (`eph_place`, from `unsent` or `parked`). A thing with state under L1 that enters L2's closure sends L2 nothing of what is held.
- `ephemeral::second_label_gets_held_state_spec_sync_9`: a window moved or added to a group: a reader of the new group gets later notes, never the state. On main too. Conflicts with "ephemeral state converges among the nodes holding it".
- `ephemeral::write_before_kept_row_returns_reaches_label_spec_sync_9`: y on L1 and L2 restarts, host lost its entries, k (L1) offline. y writes: goes under L2 only. k returns: y gets the row, the write stays out of L1, k and y read differently until y's next snapshot.

Idea: when a thing enters a label's closure (a listing or a new kept row), a writer writes one snapshot of each of its held ephemeral aspects: `eph_place` then puts it under every label, others' writes included, and it uses the existing fallen-snapshot path. Non-writers wait for a writer. Needs the things entered (`Groups::set` returns them; `placed_from` does not diff yet), and a restart's row returning must not snapshot per row at every node (only when the node holds commits on the thing that have no entry under that label).
