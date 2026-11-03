# Rename the "person actor" to "account"
> Summary: the spec and API call the actor a recovery key owns, whose admins are a user's devices, the "person actor" (`me()`); nothing ties it 1:1 to a human and people will use it for teams, bots and shared identities, so the name misleads (Tess). Rename to "account" (what it is: the root of what a user owns, administered by their devices) across spec, notes, the API docs and the CLI's `whoami`; `me()` keeps its name.
> Tags: spec, api, naming

Tess's direction. Pre-stability, so a textual rename plus any type names (`Person` in core/osis, `PERSON` records) in one branch; no wire change (the thing is an actor like any other). Do it together with issues/grant-rename-multi-actor.md or right after.
