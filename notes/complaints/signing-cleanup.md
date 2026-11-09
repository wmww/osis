# signing-cleanup
> Summary: Footguns met removing `Core::me`'s fallback and porting tests to accounts.

A node-crate test run takes 5 to 8 minutes on a loaded box; batching many fixes between runs is the only way through a port this size.
Tests hard-coding pack indices or tie-breaking on node ids (a commit and its demotion at one `ts`, packs by index in `order.rs`) were accidents of bare-node ids: an account changes both. Advance the clock or find the commit by content.
Tests parked "for causes not found" had rig causes: a helper naming the node as a removal's author (the engine then rotated for real), heartbeats read off the account, grants to the node's own account, `net.pair` left from bare ids. Check a port's helpers first.
