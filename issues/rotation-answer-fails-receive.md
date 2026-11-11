# A rotation answer that cannot be written fails the receive
> Summary: `flows::signing::answer_rotations` runs at the end of every transaction (`Engine::run`) outside any `Tx::step`, so an error from this node's own answer fails the whole transaction, a receive included, unlike `answer_removals` (a step: reported `AddendaFailed`, stays due). Reachable: `listing` writes on every thing the account's closed-epoch commits touch with `m.unchecked()` but no delete-keys wait, so a node of the account holding a commit on a thing whose `keys.0` has not arrived (a thing another account granted it write on) fails `framing_for` with Permission (Local) and refuses the receive until the keys come; `witness` and `listing` also judge the role by `role_now` and the thing as writable not at all, while `commit_in` judges at its own stamp and refuses an unwritable thing (`UnknownThing`).
> Priority: normal
> Tags: engine, security

## Direction
Each rotation answer one step, as `answer_removals`: a failure is reported and stays due (rename `DiagnosticKind::AddendaFailed` to cover both answers). `listing` waits for the delete keys of every thing it lists (`secrets::holds_delete_keys_in`, as `witness` does) and leaves out a thing that is not writable here. Test: a listing whose thing's `keys.0` comes after the rotation; the receive applies, and the listing is written once the keys arrive.
