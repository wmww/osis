# A rotation inside create_link hung a chat join
> Summary: When `create_link` rotated link key K inside the link's own transaction (K's KEM keys ride `Tx::publishing` instead), osis-chat `chat::a_member_joins_and_syncs_through_a_relay_holding_from_its_node_root_spec_sync_set_2` (then a plain join) hung instead of failing; the cause was never found. A hang means some wait never ends: find it with a hand reproducer (a thing rotating in the transaction that makes the link to it) before it shows up elsewhere.
> Priority: low
> Tags: engine, sync
