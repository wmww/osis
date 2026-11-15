# Leaving k sync IDs at once forgets and reloads k times
> Summary: leave's settle calls `forget_local` once per sync ID that stops (`Wait::Done`, read): each call scans every thing's aspects (`by_aspect`), decodes every commit header (`retention::forget`), reloads the engine (`Engine::reload`) and scans every own entry under every synced sync ID (`Live::forget_local`). Leaving a realm whose k channels each have their own sync ID costs k times O(everything held): O(k·n).
> Priority: normal
> Tags: sync, engine, performance

- Where: core/sync/src/leave.rs `Leave::settle` (one `g.forget_local(&t)` per due S), `Live::forget_local` (every `store.syncs()` × `store.entries`), core/engine/src/sync/mod.rs `Engine::forget_local` (`by_aspect` scan, `forget` with `Scope::Local`, `reload`, `reexamine`).
- notes/sync-leave.md calls it rare and per thing; unfiling or losing a group that holds many separately shared things (a realm's channels) makes k of them due in one settle.
- Fix: collect the things whose S is done in one settle, forget them in one `Scope::Local` call (one reload), unlog own entries once, then shred each S (keeping "forgotten before the shred" for crash safety). Test: leaving k = 3 and 30 separately shared things counts one reload and O(entries) unlogs at both (`osis_base::costs`).
- Lost access (`rotation/lost.rs`, also a reload per loss) is the same shape; check whether several actors lost in one step reload once.
