# A redeem dropped before its join is delivered can lock the redeemer out
> Summary: `redeem` holds the link key L until the join is at a source of K, because the sharer's node admits the redeemer only by L until it holds the join. A call dropped, or a restart, in that window forgets L (it lives in memory only); with no other node between them the sharer's node then refuses every connection (`Proved` empty, `NOT_ADMITTED`) and the join never reaches it. Calling `redeem` again does not help: `reaches` is true, so nothing is followed.
> Priority: low
> Tags: osis, node-sync

Options: on a repeat call while the join is not at a source, follow the link and hold L again (the link text is at hand); or keep the seed with the link follow (`y/l`, persisted) until delivered. Reproducer shape: like `sharing::redeem_survives_a_drop_before_the_join_arrives_spec_permissions_7` (a dropped connection, fixed), dropping the call's future (or restarting Bob) right after the join; it needs a name of its own.

A restart earlier, while `redeem` still waits on K's grant, leaves K's hint (`via` L) and the link follow (`y/l`) persisted with L gone: the node dials K's peers and the sharer for that label until `redeem` is called again, opening nothing. Keeping the seed with `y/l` would cover this too.
