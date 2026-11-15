# wait-revoked
> Summary: footguns met on the wait-revoked branch.

- A sibling's `Engine::rotate_account` (test hook) left the other sibling unable to read a thing shared with another account once that account resealed to the new epoch (node 1 read nothing after node 2 rotated, siblings World). Rotating from the node that later reads it works; not chased.
- spec_map anchors must be literal text of the cited section, including after a reflowed comment line break joins two words with two spaces: write the anchor on one line.
