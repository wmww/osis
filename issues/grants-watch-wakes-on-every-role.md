# Every grants watch re-reads on any role change anywhere
> Summary: `Filter::Grants` subscriptions sit on `Slot::Roles` as well as their own thing's slot (core/osis/src/watch.rs, `slots`), so each role change anywhere re-reads every grants watch in the process: work scaling with the watches, not with what changed. It also masks a missing targeted delivery in tests.
> Priority: low
> Tags: osis, performance

They listen on every role change because `grants(thing)` shows a roster only to a reader of the thing (`Reader::shows_roster`), and a role change on another thing may give or take this reader's read. Fast by construction (notes/principles.md) wants a grants watch woken only by what can change its answer: a role change on the thing, or one changing whether the subscriber reads it (as `role_on` follows the subscriber's role).
