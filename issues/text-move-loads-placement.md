# A text move loads the whole stored placement
> Summary: In a new session, a move of 4 chars in an 80k-char paged text loads every placement block (about 110; 1046 at 800k) where an insert or a delete loads 3. The join's prefetch (`pages::prefetch`, `dry_follow`) misses blocks until its budget runs out. Repro: osis-node `scale::repro_text_move_loads_placement`.
> Priority: low
> Tags: engine, performance

A move is O(text) in placement blocks loaded, whether the target is 50 chars away or far: spec/requirements.md Scale wants O(change). Inserts, deletes, edits, undos and reads by index stay flat (`scale::text_edits_are_flat`, tier 2). Start from the `PlaceMisses` the move's `dry_follow` reports per prefetch round.
