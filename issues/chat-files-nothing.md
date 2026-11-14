# `chat create` and `chat join` file the chat nowhere, so it does not sync
> Summary: a node syncs only its synced group's closure (spec/sync-set.md §2); `osis_chat::create` and the CLI's `chat join` (redeem) list the chat in no group, so the maker's chat and a joiner's copy never sync; the CLI user must `group add home CHAT --subgroup`.
> Priority: normal
> Tags: chat, cli

- notes/chat.md Create still says the maker's nodes "serve it with no setup": not true under the sync set rule.
- Join: the same gap as issues/sync-link-first-contact.md (Filing after the join), for chat. The app files a redeemed thing in the account group (notes/app.md, Search); the CLI and the chat library do not.
- Fix: `chat create` and `chat join` file the chat as a subgroup of `home` (an accept, spec/sync-set.md §4), or the library takes the group to file it in. Test: a chat made and joined through the library syncs with no other write.
