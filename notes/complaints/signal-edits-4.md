# signal-edits-4
- Main was red when the branch started: node `edits::` tests (19) created things with the node's tid as admin after the signing merge moved authorship to accounts (fixed here: `engine.me()`), and `fill::a_purge_comes_with_order_0` fails on main. The edits branch merged after signing on clippy alone, so the clash only showed in this worker's tier 1; `tools/bin-at main` (3 min) told old failures from new.
- Tier 1 took 11.5 min at load 25-30 (notes say about 2.5 min quiet).
- Review: the box ran at load 40-55; a single-crate `cargo test -p osis --test it edits::` build took 7.5 min cold after the claim.
