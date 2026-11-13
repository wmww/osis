# An open head off the peer's path re-registers its child forever
> Summary: sim `member_churn` setup 478483357567 seed 478483357579 storms (5000 deliveries): node 1, open on L at a peer that cannot read it, at a head the peer's path does not hold, sends the recorded child's Register, gets 9, and the next pass sends it again with no back-off; its Behind item on that head is answered 14, which an open label ignores. Passes on main; fails from net-3i2's first commits on.
> Priority: critical
> Tags: sync, sim

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 478483357579 --setup 478483357567 --only member_churn` (step 62, about 7 s; `OSIS_SIM_TRACE=1`: link 15, label 35bf69).
- Seen: node 1 Hits L on a new connection (accepted), opens at the step its walk showed (`member_unread_there`: the walk's step, `LConn::head`), asks a Behind item on it (14), then `reregister` sends `recorded_child` of that head; 9 goes to `refused`'s last `(Request::Register, _)` arm, which marks the label for a pass at once, and the pass sends the same Register. `behind_answered` returns early for a refused answer unless the phase is `Behind`.
- Likely cause: two admins' sibling steps carry the same role keys (notes/label-access.md: one child per branch, same keys, different parent signature), so a Hit by that sync key opens at the peer's sibling while this node records its own branch's step as the head; `walk_candidates` keeps each key once, so it never names the other sibling.
- Needed: a 9 on an open label's child (or a 14 on the open head's Behind item) means the open head is not the peer's; the node must find the peer's step bearing the key (another recorded step with the same keys, or a walk) and must never re-send a refused step without a back-off.
