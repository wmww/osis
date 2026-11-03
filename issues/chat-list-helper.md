# osis-chat: no way to list the chats a store holds
> Summary: An app showing "your chats" has nothing to call: osis-app scans `status().groups` for groups with `chat:settings.0^`. Ask: `osis_chat::chats(db) -> Vec<Tid>` (or a held-groups listing in `osis` it can filter).
> Tags: core-ask, chat

osis-app (`app/src/chat.rs` `chats`) reads every synced group from `Osis::status()` and keeps those whose `chat:settings.0^` reads as some value. It works for chats made or joined here or by the CLI on the same store, but it leans on the status report as an index of held groups, re-reads it on every status change (the app's chat list follows `watch_status`), and the settings aspect name is the crate's detail. A `chats` call in the crate (and a watch of the set, or a documented event to re-list on) would replace it.
