# p2p-relay
- `Sched::run` always runs to quiescence, timers included: a test that wants to act between two virtual moments (e.g. take a parked connection before its 60 s expiry) must do it inside one `block_on` with `Net::sleep`, not between `run` calls. Cost a test rewrite.
- quinn closes every connection of an endpoint on `Endpoint::close`: a `Drop` that closed a dial socket's endpoint killed the connection the dial had just returned (tier 2 only; tier 1's model keeps connections past a socket's drop). Worth remembering for any socket wrapper.
- Tier 1 ran at load 25+ beside other agents: well over the documented 2.5 min.
