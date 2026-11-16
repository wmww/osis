# Forgetting still scans four whole tables
> Summary: `retention::forget::forget` (release, lost access) finds its things, aspects and commits through the indexes and moves the indexes in place, but still scans every pending row (decoding each), every timer (`x/`, keyed by time), every `z/` named-permanent row (a thing's half of the key is second) and every freed row (`fl/` + `Indexes::freed`, keyed by blob first): O(those tables) per forgetting.
> Priority: low
> Tags: engine, performance

- Where: core/engine/src/retention/forget.rs (`each_pending`, `remove_scanned(TIMER)`, `remove_scanned(NAMED_PERMANENT)`), core/engine/src/retention/freed.rs `lost` (`remove_scanned(FREED)`, `ix.freed.keys()`).
- Each table is small next to what is held (waiting commits, timed parts, purge drops, freed links not yet judged), so no count test shows them yet; each grows with its own kind of row, not with what is forgotten.
- Levers: a pending index by thing (the waits index has the headers' things); timers found per commit (a part's timer keys from its bounds, or a per-commit row); `z/` keyed thing first; freed rows and `Indexes::freed` keyed thing first (`Engine::freed_rows` and the judge pages read them whole either way).
- Counted: osis-sync `leave::leaving_several_forgets_once_and_costs_what_left_at_n_and_10n_spec_sync_set_3`, osis-engine `scale::losing_access_forgets_what_was_lost` (commits looked at); a fix adds the table's rows to the count.
