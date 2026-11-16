# keel-laneb-follow
- On main at start: 56 osis-sync `it` tests and osis `sync::importing_a_card_gives_the_account_spec_sync_inbox_5` fail (a card redeem stays `Pending`), plus the four known engine lib tests (keel-lane-c.md). Finding that out took swapping origin/main's engine sources in and running the suites twice.
- `git checkout HEAD -- <dir>` to restore after such a swap brings back what the last commit had, not the working tree: a fix made after a wip commit was silently undone.
