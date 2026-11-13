# cleanup-schema
> Summary: Complaints from the osis-schema cleanup.

- dead_pub found nothing again; grep found five dead or test-only items it cannot see (`Type::option`, `Flag::name`, `SchemaView::ty`, `Field::new`/`Case::new`, `StaticSchema::error`), all sharing names with other types' methods.
- Comparing against main by `git checkout origin/main -- core/schema/src` in the worktree, then `git checkout HEAD -- ...` back, silently drops uncommitted edits. Commit (or wip-commit) before any such swap.
- The quickest equivalence checks were outside the test suite: `osis-schema-gen` output for every schema/*.osis and a throwaway test dumping canonical bytes, each run once on main's sources and once on the branch, then `cmp`.
- The schema value form had hand-written readers and writers for option, set, list and uint that `Codec` already provides; when a crate has `Codec`, look for code walking `Value` by hand.
