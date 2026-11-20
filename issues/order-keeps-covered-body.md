# held_set_decides_plain: a node keeps a body a held snapshot covers
> Summary: order::held_set_decides_plain (Keeps) fails at OSIS_ORDER_SEED=148495092593 on main's binary: held-model reports a commit on t:kept.0 whose body the node holds though a held right holder's snapshot covers it.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=148495092593 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). Fails on main at 592532d06 (`tools/bin-at`). Text: "now: held-model differs: commit ... on ... t:kept.0: the node holds its body, a held right holder's snapshot covers it". Not yet studied: the next step is the shrunk history as a hand-written test (notes/testing.md, Seeds are 0).
