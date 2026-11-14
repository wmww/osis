# issue-triage
- policy.py's dangling-path check does not catch an issue named without its `.md` path (e.g. notes/sync-rebuild-handoff.md's bare triage list), so renames and deletes need a manual `git grep` of the bare name too.
- Many issues cited tests by line number only; after the node tests moved to engine `it` those are unverifiable without reading both versions.
