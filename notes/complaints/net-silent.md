# net-silent
> Summary: Workflow notes from the stall-rule branch.

- The node test harness `Net::tamper` can only replace a frame, not drop it; added `Net::silent` (drop a sender's replies on one link) instead of bending tamper.
- A frame head's kind and id need 11 bytes for a node-range id (`0x1a` + 4 bytes): a partial-reply test cutting at 8 bytes looked like a bug in the peek.
