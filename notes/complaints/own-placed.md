# own-placed complaints
> Summary: Workflow snags met on the own-placed branch (local deletions under hosted labels).

- The writer keeps its previous body as well as its newest (`single_writer_replace_grows_nothing`), so a test that needs a body covered must write two newer ones, not one; a first attempt with one newer write looked like a broken guard.
- The in-flight half of `held_elsewhere` was covered by no existing test (all of osis-node passed without it); only a held-host test (`held_hosts`) reaches it.
- Review: a blob-ID-order case (which of two encryptions is lower) can only be set up by trying written values until the IDs fall right; the test asserts the order so a harness change fails it loudly instead of silently testing the other case.
- `State::load` rebuilt `deleted` from blob records, which a dropped body's `forget_blob` removes: after a restart a deleted body's tombstone no longer kept its commit from being forgotten. Now rebuilt from the kinds stored with tombstones.
- A `claudewait` call with a mistyped task ID fails as "unknown task ID ... started before the plugin was enabled?", which reads like a setup problem.
- Review 2: the brief's sweep ran before the rebase and failed `coverer_revoked` 743265354034 (an upload/delete loop between two nodes); the branch's old base fails it too and main since fixed it (reupload-loop). Sweeping after `git rebase origin/main` would have saved an hour of tracing.
