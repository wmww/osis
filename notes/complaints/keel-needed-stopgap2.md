# keel-needed-stopgap2
> Summary: mishaps removing the needed-rule stopgap from engine tests/it.

- Most engine `tests/it` receivers were role-less nodes handed plaintext packages; they kept things only because no need-judgement fired. Each needed its own fix (reader template, node of the maker's account, access delivered first). A shared "observer" helper from the start would have saved hours.
- Arrival order is the footgun: content a node cannot yet open goes at the next judgement and LocalPeer never sends it again. Deliver access (the grant, which waits for the record) before content.
- Two near-copies of `edge_write` (common vs order.rs) and of `FRESH` seeds per file: easy to collide a reader seed with a net peer's (seed 1 made a second Bob).
- Judging every record on arrival looked principled and failed 840 tests (contacts' chains go at once): recorded in issues/needed-arrival-order.md.
