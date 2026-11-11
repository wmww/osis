# inbox-fixes
> Summary: workflow notes from the inbox-copied-stale and replaced-inbox-resend fixes.

- The inbox-copied-stale repro no longer fired on main (timing moved), so it gave no before/after signal. A temporary eprintln in `InboxCopied::counted` showed the counted host set does flip (1 -> 0 -> 1 connections) under a cached label in the no_server sims; eprintln inside tests needs `--nocapture` to show.
- Reverting a fix with `git checkout <dir>` to test the old behaviour is easy to forget to undo: keep the diff in the scratchpad and re-apply it (or make a wip commit) before going on.
- Review: `InboxCopied` relies on `State::losses` for every non-monotone change of what `held_parts` reads; `set_entry` replacing a commit entry (shredded wrap in `drop_blob`, `Kind::Bad` after a prefix disagreement) bumped nothing. A cache invalidated by a counter needs every writer of its inputs audited; grep the inputs, not the obvious removers.
