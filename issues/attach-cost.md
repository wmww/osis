# Attaching a thing costs in the size of what it joins
> Summary: Adding one strong that attaches an independent thing to a root's unit pulls the enclosing unit's sync IDs anew from every source (`units::refetch`), so the attach costs in the size of the enclosing unit (counted once: 83 KB at 4 members, 141 KB at 40), against spec/requirements.md Cost. Inherent is only the retag of the attached thing's blobs.
> Priority: normal
> Tags: sync, engine, performance

What the attach needs (spec/sync-judgement.md §1 Retag): the attached thing's live blobs, and those of what it reaches, entered under the enclosing sync ID once each, and its role data logged there as certificate copies where bodies do not carry them: in the size of the attached thing. What it does: the pull anew at a new strong (spec/sync-judgement.md §3 Dropped bodies; engine `sync::units::refetch`) re-lists the whole enclosing unit.

Fix: a pull limited to the attached thing's entries, if it meets the spec's reason for the pull anew (what was forgotten of the thing is fetched again); else state why the spec needs the whole unit. Test: count bytes and deliveries of an attach at n and 10n members of the enclosing unit, and at n and 10n dependents of the attached thing, in a default test.
