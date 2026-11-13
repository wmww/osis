# The guard against a peer's forged head entering label.0 has no test
> Summary: A label opened with no head takes its head from the peer's stream. `inbound.rs` `new_head` records a child step only under a head already recorded in `label.0`, so a dishonest peer naming a forged head (the real sync key, its own delete key) and a child signed by it cannot get that chain committed into the group. No test builds such a peer; removing the guard fails nothing.
> Priority: normal
> Tags: security, tests, node-sync

- Wanted: a node test with a peer that names a forged head carrying the label's sync key under its own delete key, then a child signed by it, to a node that opened with no head. The node must not record either step, and must not sign writes or deletes under them. The test fails with the guard removed.
