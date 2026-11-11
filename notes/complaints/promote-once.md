# promote-once
- `net.group` twice for one admin gives both groups one label ID (same rotation seed): use `group_seeded` with distinct seeds. A silent footgun in tests needing two groups.
- A flood test must keep the admin offline while depositing: otherwise clearing and the duplicate-delete rule run inside `net.run()` and the host never holds more than the cap, so "past the cap" can't be shown.
- Nodes are not tied to their account under a group label (the devices actor's roster is not there): a writer cannot tell a reader node's card from a minted key actor's (issues/promotion-minted-key-actor-cards.md).
