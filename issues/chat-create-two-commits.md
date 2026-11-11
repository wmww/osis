# Chat creation is two commits with a sync between
> Summary: `osis_chat::create` (libs/chat/src/lib.rs) writes the chat's record, syncs, then writes its history setting (`retention^.0`) and settings. A failure after the first commit leaves a synced chat with no history setting or name, and nothing finishes it (unlike `add_with_grant`'s idempotent finish). Either make creation one commit (why the sync is needed first: find out; if it is the label or own secrets the settings commit needs, see whether one commit can carry both), or make `create` resumable on the half-made thing. Found by Kestrel's read-only review.
> Priority: normal
> Tags: chat
