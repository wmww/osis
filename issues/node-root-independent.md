# The node root is not kept local
> Summary: spec/sync-set.md §1 says the node root is local with no sync ID, but (1) a thing minted with admin the node root (osis `create`, whose account root is the node root), once made independent for a grant, makes its mint admin, the root, independent too (spec/permissions.md §3 holder actors): keysets and a sync ID; (2) a commit writing the root's `holds.0` beside a shared thing (making it and holding it in one commit) is logged under that thing's sync ID with the root's section sealed under its derived epoch, leaving a `dw/` row of the root that nothing lets go. Either nothing shared is minted with or written beside the root (piece 2: things made in the account), or the spec says what the root becomes.
> Priority: normal
> Tags: engine, spec

Seen in osis-sync `growth::a_redeemed_and_ended_link_returns_storage_to_a_fresh_worlds_spec_sync_set_3` (ignored, making an account: the `dw/` row after a link's round) and osis-engine closure tests, which mint shared things with the node thing instead.
