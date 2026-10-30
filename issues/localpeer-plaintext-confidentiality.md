# LocalPeer tests pass commits in plaintext: their confidentiality checks prove nothing
> Summary: osis-node multi-peer tests hand commits over with `engine.package(id)` + `LocalPeer::deliver`, unencrypted, so any peer can apply (and "read") any thing; an assertion that a peer does or does not read something there tests nothing. Only node-sync / World tests (sealed under labels) show who holds what.
> Tags: tests, node, security

Found by until-link: the joiner peer "read" the sharer's link seed thing in `flows::until_link_backdated_grant_void_spec_perm_9`.

Fix direction: make `LocalPeer::deliver` (or a variant used by confidentiality tests) seal under the label / inbox the commit would travel by and open with the receiver's secrets, refusing what it cannot open; then audit core/node/tests/it for read/not-read assertions that relied on plaintext delivery (grep `role_now(.*None`, `get(.*is_none`, "cannot read").
