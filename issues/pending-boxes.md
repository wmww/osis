# A grant delivered by inbox stays pending, and its boxes with it
> Summary: A grantee that receives its grant as an inbox blob (spec/sync.md §3) cannot apply it: the target's `/created` and the granter's chain certificates are under the target's label, which it can open only with the read secret the pending grant boxes. spec/crypto.md §4 says secrets of pending commits are "kept for reading"; node-core opens boxes only from applied `/secrets` state.
> Tags: node, permissions, sync

- Seen while testing node-sync's inbox path (crates/osis-node/tests/sync_more.rs `inbox_delivery_spec_sync_3` delivers a commit the recipient can apply; a grant on a thing it never saw pends with `UnknownCreated`).
- The sync side is ready: an opened inbox blob's `things` become label hints (`y/i`), the node dials their servers and opens with the read secret of the hinted thing (index guessed 0..4) as soon as `Engine::epochs` returns it.
- Options: (a, recommended) node-core opens the boxes of a pending membership commit addressed to this node or its actors into unestablished epochs ("kept for reading", spec/crypto.md §4: opening a label is not encrypting under), so the grantee opens the label, downloads `/created` and the chain, and the grant then applies and establishes them; (b) the inbox payload also carries the target's `/created` and the granter's chain certificates (a spec/wire.md §9 change).
- Owners: node-core (opening), membership-flows (grant tests).
