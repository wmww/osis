# A thing can require a retention for its aspects
> Summary: Retention is the writer's choice per delta, so a hostile writer can store `nobody` junk in a thing that never chose it, and apps can only hide it. Owner approves: an admin-only setting on a thing requires a retention per aspect, and a delta with any other retention is invalid and not must-hold, enforced by rule. It must generalize across core, not be chat-specific.
> Tags: spec, permissions, engine, commit, schema

Design points to settle in one general rule:
- Shape: an admin-only core aspect mapping aspect key (or pattern, for per-year names) to the required retention. Any thing, not only actors or chats: a public record document, a shared folder, a chat. Fits schema defaults: a schema default fills what a writer writes, this enforces it.
- Judgment: a delta's validity against the setting in force at its key on the role timeline, like an admin-only aspect (spec/permissions.md §5.2), so order independent and backdating gains nothing beyond what already holds. Changing the setting never rewrites earlier writes' retention (immutable, spec/commits.md §5). Check a backdated write around a change, and a demoted admin's change.
- Exempt: role-class and `created.0` (fixed retention). Compaction snapshots compute their own retention (spec/commits.md §5): required retention must not make them invalid.
- Bodies: an invalid delta under this rule is droppable and not must-hold, at every node, with no purge right. This must not reopen what `nobody` or author-only promise: only a delta that broke the thing's own rule goes.
- Works with: `PurgeBy` in osis-base (five sets; the setting names one, keep bounds alongside), notes/frontier-study.md (the permanent class: a required permanent retention makes an aspect all permanent, so a frontier never falls back to IDs for a mixed aspect, which the study left open), issues/purge-by-author.md.
- Who else: an append-only audit log; a document whose edits must stay.

From building the sets: a required `author` on an aspect a compactor may snapshot works unchanged (a snapshot is always `writer`, exempt above); an admin who sets required `author` cannot then remove bodies by purge, so the setting promises what it says.
