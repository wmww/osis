# A writer can cut kept history short by backdating its replace
> Summary: a replaced body's kept period runs from the superseding write's own `ts` (spec/commits.md §5), so any writer, with no purge right, can stamp a replace just after the write it replaces and make a body older than D leave history (and drop once covered) the moment its replace arrives; the spec calls this storage reclaim that "erases nothing", but the replaced body is erased.
> Priority: low
> Tags: security, retention

**Decided (Tess):** accepted, not built around. To do: the spec's wording (a replaced version is kept for the period after it was written; a writer's backdated replace shortens kept history, erasing what it replaces).

- The receiver cannot tell a backdated replace from an honest offline one (written then, synced later): both date at their `ts`, and both make the replaced body leave history on arrival when its `ts` plus D is past. Same on every node (stamps are node-independent); same in the full judgment (`dated_replaced_at`) and in kill rows (`Killed::note`).
- Bound: a superseder must beat the replaced write, so its `ts` is no earlier than the write's own: a body is always kept D after it was written, never D after replaced. History of a value that stayed current longer than D can be cut to nothing.
- Durable commits carry no drift cap on `ts` (only relay-only ones, spec/sync-compaction.md), so nothing bounds the backdate.
- Options for Tess: accept and fix the spec's wording ("shortens history, which a writer could also do by ..."); or date by something no single writer controls (arrival is node-dependent, so nodes would disagree), which seems to have no clean form.
