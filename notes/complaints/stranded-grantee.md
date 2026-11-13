# stranded-grantee
- `hosted_nodes` accounts have hostless inboxes and no direct links, so every grant and re-seal to them stays pending; a test that hands a grant over by `pair` then sees later re-seals vanish. The issue was filed critical from that harness artifact. Use `home_at_hosts` when a test depends on deliveries.
- Rebuilding after a cherry-pick of an engine change cost ~3.5 min per round trip; checking a branch's effect cost two of them.
