# Tier-2 `pager::tests::shape_reduced_arity` fails
> Summary: The ignored osis-store test `pager::tests::shape_reduced_arity` (`cargo test --release -p osis-store -- --ignored`) fails its last assertion: slot 7 reads the value written as 6. Likely the test assumes `alloc` hands out slots from 0 (an off-by-one in the test), but could be a pager bug; found at the wave 3 integration pass.
> Tags: storage, tests

```
thread 'pager::tests::shape_reduced_arity' panicked at crates/osis-store/src/pager.rs:942:9:
assertion `left == right` failed
  left: Some([0, 0, 0, 0, 0, 0, 0, 6])
 right: Some([0, 0, 0, 0, 0, 0, 0, 7])
```

The shape assertion before it (one row per level changed by a rotation) passes. Check what `alloc` returns for the first slot; if slots start at 1, fix the test to read the slot it wrote (`p.read(8)` holds 7), else find why a slot's row holds its neighbour's value.

Note: the failure stops `cargo test` before osis-store's other ignored test (`tests/paged.rs`) runs; it passes with `--no-fail-fast`.
