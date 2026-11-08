# Schema compatibility check
> Summary: A check that a schema file is a compatible successor of its earlier revisions: extra arguments to `osis schema check` (e.g. against every earlier revision of the file in git history) plus a library function tests can call. Not run on our own schemas until formats are stable.
> Priority: low
> Tags: schema, cli

## What
- Library: a function taking the earlier revisions (oldest first) and the new one, returning every violation; `osis_schema::check(old, new)` (one `Rule` per spec/versioning.md §4 item) is the base for each pair.
- CLI: `osis schema check FILE` parses and validates only. Extra arguments add the comparison, e.g. `--against-git` (every committed revision of FILE) or `--against OLD.osis`.

## Rules
- No aspect, field or case dropped: removal only by `reserved` (aspects: never).
- No number reused (a reserved one included).
- An existing number keeps a compatible type (spec/versioning.md §4: register embedding edges only).
- An aspect's markers change only with a new version (spec/data-model.md §2).
- Versions of one name ascend; the revision is bumped on every change.
- The "add a default to a formerly required field unless explicitly marked" escape of spec/versioning.md §4 needs a marking: an argument, or a line in the file.

## Not yet
Not run on schema/*.osis, nor by the merge gate, until formats are stable (CLAUDE.md: no backward compatibility before the stability discussion).
