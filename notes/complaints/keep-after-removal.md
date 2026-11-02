# keep-after-removal
> Summary: test-writing footguns met while building keep.

- `forge_role_commit` with a `roles.0` map writes no edge the walk sees (commit-form, no entry shape), so a test "forged write not applied" passes with the rule disabled. Only a fix-disabled probe showed it; perm's `World::set` is the honest way to test edge judgment.
- A `claudewait` loop inside one 240 s foreground call was moved to the background by the tool; one call at a time.
