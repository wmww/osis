# A node closing reaches a port client as Storage
> Summary: `Error::Closed` has no wire code: `port/codec.rs` sends it as `STORAGE "the node closed"`, so a client's wait ended by the node closing can see `Err(Storage)` instead of `Closed` or `Network`. `port::a_wait_needs_no_pump_and_connecting_to_nothing_fails` fails when the close reply beats the connection drop (about 3% with 24 copies at once).
> Priority: normal
> Tags: core, tests

Give `Closed` its own `ApiCode` and decode it back to `Error::Closed`, or send the closing node's waiters a `Network` answer. A client should be able to tell a node that went away from a broken store.
