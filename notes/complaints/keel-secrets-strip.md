# keel-secrets-strip
- `git checkout <file>` to undo one hunk for a fail-without-fix check also undid the file's other edits; patch the one line instead.
- Two cargo runs chained in one background command rebuild between them if a file is edited meanwhile: wait before editing.
- The secrets check's "want: live, got: loaded" read like a missed save; the live index was the stale one (a lost-access drop keeping history a load does not rebuild).
