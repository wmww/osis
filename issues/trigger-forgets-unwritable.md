# The trigger forgets an aspect weighed while its node could not write
> Summary: `Engine::compactions` drops an aspect's estimate when `may_snapshot` answers `Later` or `No` (keys or the thing's minting not here yet, role missing), and nothing weighs it again once the node may write: bodies held past `FACTOR` stay until the next write, expiry or flip there.
> Priority: low
> Tags: retention

`retention/compact.rs` `compactions`: `may != Yes` removes `est`. Becoming able to write (keys or minting arrive, a role granted) marks nothing due, so a quiet aspect whose held bodies cost more than `FACTOR` times its snapshot keeps them at this writer until a write, expiry or validity flip of it arrives; the estimate also starts from 0 then, but the next write weighs in full. Restarts lose the estimate the same way (in memory), so the same holds after an open. Seen in churn seed 807204138389: 26 weighings at writers answered `No` (`win:cursor+.0`, `win:flag+.0`, after restarts). The quiet rule (spec/sync.md §7 Cover once quiet) covers the case where the aspect holds a leftover, and only if the node may write when its quiet time ends: one that may not then is not armed again until the next stir.

Fix shape: wait as purge-on-replace covers do (`Indexes::cover_waits`, `replace::wake_covers`) and weigh the aspect when it wakes; weigh every compactable aspect held past a mark at open.
