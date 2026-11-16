# fathom-proofs-stop
- `World::run` moves the world clock by its dial ticks (about an hour on `contacts`), so a grant `until` a minute ahead has passed before the grantee reads; and `World::advance` over `LOST_HEARD_WAIT_MS` (90 days) took about 250 s of dial ticks. `World::skew` of the one node moves its clock alone in milliseconds.
- `World`'s engine `now()` lags the world clock until the node steps: an `until` from `engine(i).now()` can already be past.
- Review: `run.sh netopen O_rk3.cfg O_kk3.cfg O_rx3.cfg ON_peermoves.cfg` under heavy hit its time limit (598 s wall, O_rk3 351 s at load 13); the by-name 3-connection runs carry the module's limit, not their own.
