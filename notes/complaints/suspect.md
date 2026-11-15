# suspect
- (review) Staging a first sync not ended in a World test is cheap: take the store's `F/` row away through `WNode::store` (`with_tx`) and put it back with `set_first_synced`; both gates are tested so.
- `Engine::package(c)` after a purge of c returns the header only: package a paged commit before purging it, else a "paged" check sees one blob.
- A paged map write in a World test needs a schema aspect (`StaticSchema` map type): a raw `Ak` with `Value::Map` is one atomic value.
