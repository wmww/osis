# Spec audit: node-to-node protocol and transport gaps
> Summary: The spec audit of spec/sync.md and spec/wire.md §5-§13 left one replay-cursor nit: a cursor keeps 63 bits of a blob ID, so a replay page can skip an ID sharing them.
> Tags: spec, sync, transport

## Code nit
- Replay cursor position keeps 63 bits of a blob ID, so a replay page can skip an ID sharing them with the last one sent (`serving.rs` `replay_pos`/`after_pos`). Negligible, but a full-ID position would be exact (the cursor is opaque in spec, so the change is free on the wire).
