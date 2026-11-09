# signing-cleanup
> Summary: Footguns met removing `Core::me`'s fallback and porting tests to accounts.

A node-crate test run takes 5 to 8 minutes on a loaded box; batching many fixes between runs is the only way through a port this size.
Tests hard-coding pack indices or tie-breaking on node ids (a commit and its demotion at one `ts`, packs by index in `order.rs`) were accidents of bare-node ids: an account changes both. Advance the clock or find the commit by content.
