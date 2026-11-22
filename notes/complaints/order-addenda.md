# order-addenda
> Summary: Workflow snags met chasing the order::held_set_decides_plain Addenda seed.

- The issue's "Addenda" label misled: the failure had nothing to do with addenda (it failed with `addenda: false` too). Replaying the shrunk script with each `Cfg` knob off first (addenda, clock, model, withhold) would have said so in one run.
- `OSIS_ORDER_DUMP` prints "no header" for packs the order's node does not hold, so a pack whose bytes are another commit is easy to miss; decoding `played.packs[i].bytes` and comparing with `pk.id` showed it at once.
- The shrink waited ~100 s for the heavy lock and ran 430 s for 76 candidates.
