# Every grants watch re-reads on any role change anywhere
> Summary: `Filter::Grants` subscriptions sit on `Slot::Roles` as well as their own thing's slot (core/osis/src/watch.rs, `slots`: the roster shows only to a reader, and a role change anywhere may show or hide it), so each role change re-reads every grants watch in the process: work scaling with the watches, not with what changed. It also masks a missing targeted delivery in tests, since any role change reaches every grants watch.
> Priority: low
> Tags: osis, performance

Fast by construction (notes/principles.md) wants a grants watch woken only by what can change its answer: a role change on the thing, or one changing whether the subscriber reads it. A review of listeners took five test shapes to isolate a per-(thing, actor) roster follow, since every way an actor's access ended also woke every grants watch through `Slot::Roles`.
