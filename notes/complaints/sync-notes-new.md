# sync-notes-new
- notes/sync-boundary.md mixed a Phase 2 plan, an inventory of deleted code and per-module build logs; its "Not built" lists had gone stale in both directions (payload hints were built through `ih/` rows; held elsewhere for own entries still `NotBuilt` with no issue). Module owners should keep a "Not built" line in an issue, not a note, so it gets deleted when built.
- Several code doc comments still claimed facade calls were not built (`core/engine/src/sync/mod.rs` header) or pointed at note sections by name; section-name pointers break silently on a rename (tools/policy.py checks paths only).
- `osis_sync::types::SourceEvent` and `InboxOpened::hints` look dead (no reader); left for cleanup.
