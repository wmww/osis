# Role and sync paired: what is left
> Summary: The pairing has landed (spec/sync.md §2): a commit giving a thing role secrets of its own makes its one sync ID. Left: removing replacement (index > 0), which waits for issues/net-one-peer.md. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, spec, engine

## Replacement (index > 0)
Decided (Tess): replacement goes, after issues/net-one-peer.md.
- Its one cause: a removed admin still holding the delete key registers a child with keys only it knows at a server before the honest step gets there, locking holders out there (notes/label-access.md, Replacement labels). After net-one-peer a serving node that reads the group needs no first-come registration, and a peer that cannot read is by default the user's own node, where the remedy is local (drop the registration, or the group's readers drop the peer).
- Then going: the index in key derivation, `replaced`, `replace_label`, retiring, `register_path` for replaced labels, the index in hints and payloads, "one live" in place of "one", issues/replaced-inbox-resend.md. Stays: re-registering a recorded path at a peer that lost its data.
- Checked no other cause of a lost sync ID exists: with `unsync` gone, nothing in the engine or the API marks a label replaced except `replace_label`, and only tests and the sim call it; a label a host lost is re-registered from its recorded path; a group's readers keep the keys; concurrent admins giving a thing secrets make two live sync IDs of index 0, which both sync (an accepted fork, not a loss).

## Unsure
- (design) **Key actors** (nodes, link keys, recovery keys) have no role secrets of their own, so no sync ID: they hold roles and sync others' sync IDs. A link key starts from its link text, a recovery key from its card (both by static entry, spec/sync.md §5 Claim), a node through its account's secrets or by pairing. How shared-set matches the first two (by static entry): issues/net-first-contact.md.
- (design) Costs (issues/net-shared-set.md, Costs; tick: issues/idle-pass-per-label.md): each shared thing now costs a sync ID, its `label.0` and a home-label inbox.
