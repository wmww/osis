# review-crdt
- Finding every caller of one method (`Stamped::insert`) across crates had no tool: grepping field names collides with plain maps; a temporary `#[deprecated]` plus `cargo check --workspace --all-targets` listed them exactly.
