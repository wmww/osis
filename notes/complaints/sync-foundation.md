# sync-foundation
> Summary: Footguns met laying the sync rewrite's foundation (the osis-sync skeleton, harness and engine facade).

- notes/architecture.md still described osis-node and osis-host after the deletion commit; the crate map is easy to forget when a crate goes.
- `LabelId` was the type every sync module names; renaming it to `SyncId` touched 46 files across 12 crates (a scripted `sed -w`). Any Fathom branch still writing `LabelId` breaks at rebase: the fix is the same sed.
- The facade's names collided with engine methods of the old shape (`seal`, `ingest_relay`): the facade took `seal_body`, the old `ingest_relay` became `ingest_relay_blob`.
