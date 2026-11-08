# One unkept part blocks restoring undos on its aspect
> Summary: `undo::replaced_kept` counts every earlier part of the aspect back to the newest kept whole one (snapshot or root reset) as possibly replaced (a write does not record what it overwrote), so one part with no history (an untyped or CLI write, a per-write retention of none) on a map, set or list blocks restoring undos and redos there until a kept snapshot or whole write follows it. Precise judgment needs to know what the undone write overwrote, which a dropped body cannot tell.
> Priority: normal
> Tags: engine, undo, tess-call

The rule (spec/commits.md §7): a restoring undo needs each valid part of the aspect ordered before the undone part, back to the newest kept whole part, kept or keeping by its own retention counted from the undone part's `ts`. It is deterministic and never writes back less than the state before, but conservative: a part in that span that died before the undone write still counts, since telling that needs its body, and an unkept body may be dropped (judging held bodies would make the answer depend on housekeeping). A register aspect is bounded by its last kept set; a collection only by a kept snapshot or a whole `set`.

Seen: on a `keep_history(1d)` map, one entry written untyped and its undo work, but then no removal on that map undoes or redoes until a kept snapshot (`redo_follows_undone_write_spec_commits_7` uses separate things for this reason). On a thing edited from both the app and the CLI this is user-visible.

Options:
- Accept: mixed retention within one aspect forfeits restoring undo there (state it in notes/api.md).
- Writers stamp the aspect's retention on untyped writes when a schema is known at the receiver: not deterministic (schema registration is node-local).
- A write records what it overwrote (the parts or stamps its resets reach): exact, a wire change to every restoring write.

Related gap: a forgotten memory commit (ephemeral, `unindex_commit`) leaves the candidate set, so on an ephemeral aspect an unkept predecessor that was forgotten no longer blocks: the undo writes back less than the state before.
