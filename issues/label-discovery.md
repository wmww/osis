# Label discovery, registration chains and the home label
> Summary: Nothing says where a group records its label IDs, which servers hold them, or how a server that never met the admin learns the current role keys; a `/label` aspect with a signed registration chain and a home label per actor are proposed, not designed.
> Tags: sync, permissions, networking

Review 2026-10-16, gap already named in plans/protocol-spec.md item 5. Pieces that must fit together:
- Registration: re-registrations rotate the role keys and are signed by the hard-delete key, so a server needs every step since the one it last saw. Proposal: a chain with sequence numbers, each message signed by the previous key, stored on the group thing and relayed by any member (notes/sync.md, Authorization).
- Discovery: a `/label` aspect on the group thing (label IDs, chains, servers) so a new device knows what to sync; a label ID in a link or invite for first contact.
- Home label: every actor is synced as a group of itself so its membership-class commits always have a label (notes/permissions.md); who registers it and when.
- A reader who observes a group-membership change cannot soft-retire under the old label; define who retags and when stale entries leave.
- Delete tokens for a commit spanning things with different write secrets (several owners or reader sets, one blob per projection): the `purge`-class token derives from the touched thing's write secret, so each projection likely needs its own salt and token hash in the header. Pick a rule.

Design with the first-contact invite format and the blind-server account model (plans/protocol-spec.md item 10).
