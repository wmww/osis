# standing-memo
> Summary: footguns met finding a world case where only J of a peer moves.

- "Not served" alone missed the plant: a departed peer served by a member never re-judged takes its own removal in the same batch as the write and drops S in that step, so a per-step `held_of` check never sees the write. What it observably took is the removal commit (`holds_commit`) and S no longer held.
- A pairing before the change makes the reconnect prove the account's new key, so the take re-judges every member and hides the path under test: go away and back once more after pairing.
- `tools/mutate.py ... | tail -15` cut the table rows; read the per-mutant logs instead.
