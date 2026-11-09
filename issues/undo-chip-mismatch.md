# The Undo chip can disagree with Undo
> Summary: the about facet enables Undo by `Data::can_undo` (`undo_target`), but `undo` can still fail `NotUndoable{Superseded}` (undo_target reports only `ContentGone`, notes/api.md Undo targets), and pending typing is not counted: during a typing pause the chip reads inert or "Can't undo" while pressing Undo would commit the typing and undo it.
> Priority: low
> Tags: kit, osis

- Superseded: notes/listener-design.md (undo leak paragraph) says `undo_target` fails as the call would; notes/api.md and the code say `Superseded` shows only on the call. Settle one: either `undo_target` checks that the revert writes something, or the note changes and the chip accepts a failed press.
- Pending typing: the chip is computed at render from committed history; the about section is not rebuilt per keystroke, and `TextSession` exposes no "has pending typing". Up to `idle_commit` (2 s) after typing the chip lags.
