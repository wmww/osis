# self-verifying-epochs
> Summary: Workflow notes from the self-verifying epochs branch.

- `grep -o '.\{0,150\}pat.\{0,150\}'` fails here: `grep` is ugrep, which rejects the bounded repeat ("exceeds complexity limits"). A short python `re` loop works.
- A 16-to-32-byte nonce change touched ~70 hand-written `Epoch::new(n, [x; 16])` in tests across 8 crates; tests now need epochs a secret names (`Epoch::derive`) wherever a box or history box is sealed, since sealers check.
- Review: editing label sources while the background oracle script's `cargo test-net` build was still compiling made that build fail (it picked up half the edit); finish the oracle builds before editing, or rerun them after.
