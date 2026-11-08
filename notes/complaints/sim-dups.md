# sim-dups
- The plan's example premise was off: a promoter's own certificate copies count as placed (`held_parts_at` adds `mine` whatever the host holds), so losing the copy's upload never reaches the chain check in `promote`. The check acts only when the promoter cannot complete the chain; found by trial, after building per-entry Upload/Sync loss that turned out unneeded.
- A node that never saw a commit does not know it is in a chain (`current_keys` reads applied state): "w never got the keyset" makes the chain look complete, not missing. A header-only copy is what makes it known but uncopyable.
- Node seeds pick the commits: debugging by commit ID across test edits that shuffled node seeds sent me after the wrong node's keyset.
