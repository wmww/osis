# eph-cursor-unread
- The sim trace's `link N -> Hub(..)`/`-> Node(..)` names the receiver, not the sender; easy to misread which side streamed a `-blob` event.
- No per-node log of node-sync decisions: finding why a node deleted an entry took temporary `eprintln!`s in `pass/delete.rs` and `apply/unindex.rs`.
- A first minimal reproducer passed under the old oracle because a reader whose account home the admin could not reach never learned its role (`readers` silently dropped it); check that the node under test is in `readers` before trusting a pass.
