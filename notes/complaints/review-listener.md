# review-listener
> Summary: footguns met reviewing the listener-actor branch.

- Isolating the per-(thing, actor) roster follow took five test shapes: every way an actor's access ends that I built also raised a `LostAccess` `Event::Changed` on a `secrets.0`, which reaches every grants watch through `Slot::Roles`, so a mutation of the follow survived each. A probe printing which `Msg` reaches each sub (`Msg` has no `Debug`) found it in one run; do that first.
- `Filter::Grants` subs sit on `Slot::Roles` too (watch.rs `slots`): any role-class change anywhere re-reads every grants watch, which masks a missing targeted delivery in tests.
