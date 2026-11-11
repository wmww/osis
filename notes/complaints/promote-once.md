# promote-once
- `net.group` twice for one admin gives both groups one label ID (same rotation seed): use `group_seeded` with distinct seeds. A silent footgun in tests needing two groups.
- A flood test must keep the admin offline while depositing: otherwise clearing and the duplicate-delete rule run inside `net.run()` and the host never holds more than the cap, so "past the cap" can't be shown.
- Nodes are not upstream of their account in a group label's view (they hold the account's devices actor, whose roster that label does not carry): a writer cannot tie a reader node's card to the label, so promotion takes any key actor's own card.
