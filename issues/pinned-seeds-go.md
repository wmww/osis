# Pinned seed tests go
> Summary: About 79 tests (`*_seed_<n>`, `order::arrival_order_found_histories*`, pinned order-harness histories in `judgment.rs` `found()`) replay one random seed. They are slow, and they stop reproducing anything once the harness, wire bytes or rng use change. Turn each into a small minimal reproducer of the property it guards, or delete it when the property is unclear, no longer relevant or covered elsewhere. Afterwards nothing in notes asks for seed stability (notes/ephemeral.md's "one rng draw per open" reason, notes/build.md "moves seed-pinned tests").
> Priority: normal
> Tags: tests
