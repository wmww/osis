# purge-3001
- A shrink of seed 3001 took 4 minutes for an 18-step history; the unshrunk replay (0.7 s) plus DBG prints in `deliver_with` and `purge.rs` found the cause faster.
- The oracle interleaves many fresh nodes' work in one log; printing a marker per `deliver_with` was needed to tell the as-made node from the reversed one.
