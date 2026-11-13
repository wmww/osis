# App code citing deleted issues
> Summary: three citations of deleted issues remain, each beside code working around them: `libs/kit/src/store.rs` `undo` (undo-creation-unplaces: a refusal to undo a creation), `libs/kit/src/store.rs` sharing through a tag (group-access-follows-membership), `app/tests/it/share.rs` (tag-sharing-op). Check each against the API as it is, delete what's obsolete, keep what still guards something.
> Priority: low
> Tags: app, api

For each: read the deleted issue in git (`git log --all -- issues/<name>.md`), check whether the API now does it, write a test in the app's test binary for what the workaround guarded, then remove the workaround or point the comment at a live issue.
