# One unkept part blocks restoring undos on its aspect
> Summary: Accepted limit (spec/commits.md §7): `undo::replaced_kept` counts every earlier part of the aspect back to the newest kept whole one as possibly replaced (a write does not record what it overwrote), so one part with no history (an untyped or CLI write, a per-write retention of none) on a map, set or list blocks restoring undos and redos there until a kept snapshot or whole write follows it. Rare, deterministic, fails safe; lifting it needs writes to record what they overwrote.
> Priority: low
> Tags: engine, undo

A part in that span that died before the undone write still counts, since telling that needs its body, and an unkept body may be dropped (judging held bodies would make the answer depend on housekeeping). A register aspect is bounded by its last kept set; a collection only by a kept snapshot or a whole `set`.

Seen: on a `keep_history(1d)` map, one entry written untyped and its undo work, but then no removal on that map undoes or redoes until a kept snapshot (`redo_follows_undone_write_spec_commits_7` uses separate things for this reason). On a thing edited from both the app and the CLI this is user-visible.

Ways out, if it ever matters:
- A write records what it overwrote (the parts or stamps its resets reach): exact, a wire change to every restoring write.
- Not this: writers stamping the aspect's retention on untyped writes where a receiver knows the schema; schema registration is node-local, so not deterministic.
