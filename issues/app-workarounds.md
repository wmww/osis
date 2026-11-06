# App workarounds for closed issues
> Summary: `app/src/data.rs` cites four issues since deleted (api-change-time, undo-creation-unplaces, api-deleted-known, api-subgroup-parents) and keeps code working around them: its own `changed()`, a refusal to undo a creation, and others. Check each against the API as it is, delete what's obsolete, keep what still guards something. Autonomous work.
> Tags: app, api

For each: read the deleted issue in git (`git log --all -- issues/<name>.md`), check whether the API now does it, write a test in the app's test binary for what the workaround guarded, then remove the workaround. Grep the rest of `app/`, `libs/` and `cli/` for other citations of deleted issues and handle them alike.
