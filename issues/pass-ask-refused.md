# A refused pass-end Sync is not asked again
> Summary: A Sync `ask_pass_ends` sends to a live label for a pass end after a role commit from elsewhere, refused with a code other than NOT_OPENED or UNKNOWN_LABEL (which reopen; a rate limit, say), clears `syncing`/`ending` and nothing asks again: the pass end waits for that label's next push or reconnect, as before the ask existed. Re-asking at once could loop against a refusing host; a retry at the next tick would fit.
> Priority: low
> Tags: node, sync

- Where: `open.rs` refusal handling, `(Request::Sync, _)` arm.
- Effect: `complete_pass` of the actor (re-seals, unties, history adds, link finalization) waits on a quiet label after a refused ask.
