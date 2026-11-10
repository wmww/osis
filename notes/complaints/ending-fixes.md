# ending-fixes complaints
- A hostile re-minting test needed two writer-rule escapes under `skip_writer_rules` ("thing already exists", and a re-mint of a held record writing over no state, else the equal value writes nothing): `commit_hostile` alone cannot mint a held record again.
- Offline nodes in `Net` get no `Tick`, so an expiry never runs there: call `engine(n).tick()` by hand.
- `cargo test -p osis-node --test it` took 18 min wall at load 21-25 (1081 s of tests): the one full run per change is the slow part of the loop.
- The brief's five issues are each a design step (the ending rule had three cycles to break before code): one branch per issue would have kept reviews small.
