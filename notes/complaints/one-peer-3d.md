# one-peer-3d
- Three test harnesses (osis-node `tests/it/net`, osis-sim `world.rs`, osis-sim `net/`) each glue engines to hubs their own way; 3d had to teach all three node hubs. A shared sans-I/O "node with its hub" pump would have saved most of it.
- The sim world's `set_online(false)` discarded the node's pending actions (`take_actions`), leaving a dial pending forever; only a new test (a node gone offline right after `place`) showed it.
- `ServingPolicy::connections` (host^.0) is now every connection's cap, which reads oddly under "serving" terms; a later API pass may want it as a node setting.
