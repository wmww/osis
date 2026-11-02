# history-read
- `git rebase` of several wip commits conflicted per commit in order.rs; squash wips first (`git reset --soft $(git merge-base HEAD origin/main)`).
- A new `records.rs` prefix silently collided with `SUSPECT` (`q/`): tier 1 and the small order test passed; only `reload` in the large order test said `Corrupt("short record")`. No check that prefixes differ.
- Purge test helpers: the engine refuses a purge with no delta (`Misuse`), no hint in spec until now.
- Disk went under 8 GB with others running; pruning my own `target/debug/incremental` sessions freed 2.5 GB.
