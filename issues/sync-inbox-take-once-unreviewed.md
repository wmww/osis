# The inbox take-once change merged unreviewed
> Summary: commit 0436a9dcf (an inbox blob taken once) reached main without its own reviewer; read it as a review would: the take-once map (`held::taken`), `Prefix::inbox_shaped` refusing a blob before any key is read, and `Engine::holds_commit`.
> Priority: normal
> Tags: sync, security, tests

- What it changed: a blob whose commit applied is taken once (`held::taken`, `holds_commit`); a re-take writes nothing when nothing changes; an entry whose prefix no inbox blob has is opened by no key (core/blob/src/inbox.rs, core/engine/src/sync/inbox.rs `inbox_shaped`).
- Questions for the review: can a hostile peer make `taken` grow without bound or skip a blob that later carries something new (a blob taken before the commit's records arrived); does `inbox_shaped` refuse any genuine inbox blob (a prefix shape the spec allows); a mutation per rule failing a test.
