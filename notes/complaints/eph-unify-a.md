# eph-unify-a complaints
> Summary: worker mishaps on eph-unify step A: a sabotage loop that clobbered a source file, a stdin-blocked `cat`, and the rejudge rebuild writing memory state durably.

- A "disable each fix, run, restore" shell loop backed up two files named `mod.rs` into one scratch dir; the restore copied `retention/mod.rs` over `apply/mod.rs`. Back up under path-derived names (`apply_mod.rs.bak`), or commit a wip first and restore with `git checkout`.
- A stray `cat > file` with no heredoc blocked on stdin until the 2-minute tool timeout.
- `validity::rejudge_once`'s rebuild of a memory aspect ran in the durable class and wrote its state as a durable row; only the store's debug assertion ("a memory row over a durable one") showed it, once a test flipped a memory aspect valid during a durable ingest. Fixed (`in_class` per aspect); other durable-transaction paths touching memory aspects (issues/eph-unify.md Left item 3) may hide the same.
- Writing a Net-level repro that needs a writer to act past its role took several rounds: `demote` (not a raw `roles.0` op) is a writer's self-removal, and own covers past the role needed a `skip_writer_rules` exemption in `coverable`.
