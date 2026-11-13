# cleanup-schema
> Summary: Complaints from the osis-schema cleanup.

- dead_pub found nothing again; grep found five dead or test-only items it cannot see (`Type::option`, `Flag::name`, `SchemaView::ty`, `Field::new`/`Case::new`, `StaticSchema::error`), all sharing names with other types' methods.
- Comparing against main by `git checkout origin/main -- core/schema/src` in the worktree, then `git checkout HEAD -- ...` back, silently drops uncommitted edits. Commit (or wip-commit) before any such swap.
- The quickest equivalence checks were outside the test suite: `osis-schema-gen` output for every schema/*.osis and a throwaway test dumping canonical bytes, each run once on main's sources and once on the branch, then `cmp`.
- The schema value form had hand-written readers and writers for option, set, list and uint that `Codec` already provides; when a crate has `Codec`, look for code walking `Value` by hand.
- Reviewer: hit the same swap footgun despite the line above: a reviewer fix made between two swaps was dropped by `git checkout HEAD -- core/schema/src`. A differential of a library crate's behaviour (not a binary, so `tools/bin-at` does not help) needs a supported way to build main's crate sources beside the branch's, e.g. a `tools/src-at main <crate>` that swaps in and out around a wip commit.
