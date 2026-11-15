# wait-revoked
> Summary: footguns met on the wait-revoked branch.

- A sibling's `Engine::rotate_account` (test hook) left the other sibling unable to read a thing shared with another account once that account resealed to the new epoch: that is issue sibling-rotation-drops-home (the sibling never takes the new seed), fixed on branch sibling-home (reproduced on this branch, passes on sibling-home). Rotate from the node that later reads until it merges.
- spec_map anchors must be literal text of the cited section, including after a reflowed comment line break joins two words with two spaces: write the anchor on one line.
