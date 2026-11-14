# sync-foundation
> Summary: Footguns met laying the sync rewrite's foundation (the osis-sync skeleton, harness and engine facade).

- notes/architecture.md still described osis-node and osis-host after the deletion commit; the crate map is easy to forget when a crate goes.
- `LabelId` was the type every sync module names; renaming it to `SyncId` touched 46 files across 12 crates (a scripted `sed -w`). Any Fathom branch still writing `LabelId` breaks at rebase: the fix is the same sed.
- The facade's names collided with engine methods of the old shape (`seal`, `ingest_relay`): the facade took `seal_body`, the old `ingest_relay` became `ingest_relay_blob`.
- Review: a skeleton whose every stub ignores its arguments type-checks any signature, so a shape that cannot carry a flow (settles with no way to send, a member change nobody hands to streams) compiles and passes; walking two flows on paper found both. Walk a flow per module signature before stubbing it.
- Review: `cargo test -p a -p b` stops at the first failing test binary (a known failure in osis-engine's `it` hid every later crate); use `--no-fail-fast`.
