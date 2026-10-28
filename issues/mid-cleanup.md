# Mid-layer cleanup leftovers
> Summary: Simplifications found in the osis-label/commit/keys review and not done: value accessor helpers copied into seven crates, two blob error types with lossy two-way conversions, delete-level numbers spelled out in three crates, a separate label test binary, overlapping tree-reader tests. Behaviour-preserving; none blocks anything.
> Tags: label, commit, keys

- **Value accessors everywhere**: `uint`/`as_uint`/`opt`/`as_opt`/`as_bytes::<N>`/`as_list` exist per crate with that crate's error (commit `cbor.rs`, label `cbor.rs`, crdt `wire.rs`, schema `form.rs`, proto `dec.rs`, crypto `boxes.rs`, engine `records.rs`). `Option`-returning accessors on `osis_base::Value` would leave each crate a one-line `.ok_or(Error::Malformed(..))`.
- **Two error types around one tree**: osis-label `Error` and osis-commit `Error` convert both ways (`label/src/error.rs`), losing detail each way (`Corrupt` <-> `Verify("content hash")`, `UnknownFraming` -> `UnknownVersion`, a crdt error's class mapped to a stand-in variant). The tree, list and blob plugs could share one error.
- **Delete levels as literals**: 1/2/3 appear as `keys::delete::LEVEL_*` (unused outside), label's `AUTHOR_CHAIN`, and bare numbers in commit (`keys.rs` `delete_keys`, `builder.rs` and `validate.rs` `level == 2`, `header.rs` `1..=3`) and label (`blob.rs`, `auth.rs`). One set of constants (osis-base `format`) would do.
- **`core/label/tests/scale.rs`** is a separate test binary; the convention is one `tests/it/` binary per crate.
- **Tests**: commit `tests_review.rs` `tree_reader_bounded`/`tree_short_nonfinal_chunk_rejected` overlap `tree.rs` `reader_bounds_spec_wire_6` (through `read_list`); commit's `tests*.rs` files could be one `tests/` module tree.
- `osis_commit::retention` exports helpers no other crate calls (`check_retention`, `delete_levels`, `fixed_retention`, `purge_keep_until`); `pub(crate)` would shrink the surface.
