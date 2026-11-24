# A writer can cut kept history short by backdating its replace
> Summary: A replaced body's kept period runs from the superseding write's own `ts` (spec/commits.md §5), so any writer, with no purge right, can stamp a replace just after the write it replaces and make that body leave history (and drop once covered) on arrival. Accepted (Tess); left: the spec's wording, which calls this storage reclaim that "erases nothing".
> Priority: low
> Tags: security, retention, spec

**Decided (Tess):** accepted, not built around. To do: the spec's wording (spec/commits.md §5, the line on a writer stamping early): a replaced version is kept for the period after it was written; a writer's backdated replace shortens kept history, erasing what it replaces.

Why no fix: a receiver cannot tell a backdated replace from an honest offline one (written then, synced later), and dating by arrival would make nodes disagree. Bound: a superseder's `ts` is no earlier than the replaced write's, so a body is always kept D after it was written, never D after it was replaced. Durable commits carry no drift cap on `ts`.
