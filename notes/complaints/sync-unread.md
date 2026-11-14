# sync-unread
- The brief pointed at branch `memo-effects`, which was in no ref of this repo when the module started (it merged to main minutes later); a stand-in was nearly written. Briefs naming a branch should check it is reachable.
- The engine facade returns whole maps (`sync_set`, `sync_records`, `removal_notices`): a kept-unread module that must do work per change has to diff each map on every change of it (O(map) per change). Per-key facade values or a `Feed` of changed keys would remove the diff.
