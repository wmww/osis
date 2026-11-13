# status-listener
- A thin client's `on_status_change` re-read `status()` on the dispatcher, where `may_wait` is false, so it never had the node's groups either: the dispatcher-cannot-wait rule silently empties any merged read made from a callback. `status()` in a callback still lacks groups at another node (documented on `status`).
