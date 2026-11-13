# Chat creation is two commits with a sync between
> Summary: `osis_chat::create` (libs/chat/src/lib.rs) writes the chat's record, syncs, then writes its history setting (`retention^.0`) and settings. A failure after the first commit leaves a synced chat with no history setting or name, and nothing finishes it (unlike `add_with_grant`'s idempotent finish); the doc comment says to make another. Make `create` resumable on the half-made thing, or one commit.
> Priority: normal
> Tags: chat

Why the sync comes first: a joiner reads the record among the role commits (notes/chat.md, As built), so one commit would need the record and settings to travel together under that rule.
