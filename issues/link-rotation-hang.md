# A rotation inside create_link hung a chat join
> Summary: while `create_link` still rotated K inside its transaction (before 53439ab0c moved K's KEM keys to `Tx::publishing`), osis-chat `chat::a_chat_made_and_joined_syncs` hung instead of failing; the cause was not found. A hang, not a failure, means some wait never ends: find it with a hand reproducer (a link whose K rotates in the link's own transaction) before it shows up elsewhere.
> Priority: low
> Tags: engine, sync
