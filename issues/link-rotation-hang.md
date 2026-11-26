# A rotation inside create_link hung a chat join
> Summary: When `create_link` rotated link key K inside the link's own transaction (K's KEM keys ride `Tx::publishing` instead), osis-chat `chat::a_chat_made_and_joined_syncs_spec_sync_set_4` hung instead of failing; the cause was never found. A hang means some wait never ends: find it with a hand reproducer (a thing rotating in the transaction that makes the link to it) before it shows up elsewhere.
> Priority: low
> Tags: engine, sync
