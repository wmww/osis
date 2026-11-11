# one-peer-3d
- Three test harnesses (osis-node `tests/it/net`, osis-sim `world.rs`, osis-sim `net/`) each glue engines to hubs their own way; 3d had to teach all three node hubs. A shared sans-I/O "node with its hub" pump would have saved most of it.
- The sim world's `set_online(false)` discarded the node's pending actions (`take_actions`), leaving a dial pending forever; only a new test (a node gone offline right after `place`) showed it.
- `ServingPolicy::connections` (host^.0) is now every connection's cap, which reads oddly under "serving" terms; a later API pass may want it as a node setting.
- Review: the rebase onto pending-bound conflicted only where 3d deleted `serve_with`; main's budget changes merged silently into the rest, but the once-a-second prune after a refusal lived in the deleted code and had to be moved by hand (`prune_due`).
- A hand-driven member session in node tests answers no Pull, so any test that advances past the stall time (2 min) loses it to the stall close, not to the rule under test.
- Review: the cap's tie between sources holding equally many idle connections went to the highest source (`max_by_key` keeps the last), so a flood from sources ordered below a newcomer's evicted it at every arrival; no test had more than one source (hand peers had none: `hand_accept_from`).
