# An admin by edge cannot reach a holder outside the group owning the item
> Summary: Bob, admin by an edge on an item owned by group G, grants it to Dan, who does not read G: `grant` succeeds, Dan never knows the item, nothing says why, even with a label on the item. The same grant by the item's owner works, as does Bob's on an item owned by a person.
> Tags: node-sync, osis

Found while tracing issues/item-grant-unreachable.md (solved). Repro in `sync::a_grant_on_someone_elses_item`, with `let t = item(&alice, g, g, ..)` instead of `shared(..)`, and `alice.sync(t, &[])` before the edge to rule the new label out: `dan.knows(t)` stays false; no invite request; only `deposit refused: code 13` diagnostics, which also appear in the runs that work. Not traced further; first suspect: Dan can't verify Bob's chain without G's records.
