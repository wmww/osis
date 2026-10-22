# Joins at a Slots position cost O(n) clones and re-embeddings
> Summary: Every join at a `Slots` position (a `string` upgraded to `text`, spec/crdt.md §7) re-embeds the register into each member, prunes every member and clones each member to test it against the embedding: on a text upgraded from a 10^5-char string a received one-char insert joins in ~1.1 s and a two-op batch takes ~3.5 s; the placement cache is dropped by the prune each time.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` ("upgraded text").

- `state::prune_slots` joins `embed(reg)` into every member (10^5 `Derived` records built and joined), then `Fragment::prune` on each member (`seq::prune_elems` drops the placement cache even when nothing is pruned), then `assemble` → `below_embedding` clones the member and joins the embedding again to compare.
- Cost-only directions: re-embed only when the register slot or a member's reset changed in this join (or a member arrived whole); skip the prune of a member when nothing lies below the position's reset (keeping its cache); decide `below_embedding` without cloning (a member with any record or write not in the embedding adds something). Each keeps the canonical form; the lockstep slots tests check it.
