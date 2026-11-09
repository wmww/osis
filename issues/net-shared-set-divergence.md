# S can differ between the two sides with nothing to repair it
> Summary: The two sides' S diverge after a restored store, a lost reply or a tester declining an accepted Hit. A member the server does not share is then served as an empty stream and judged caught up, and its cursor passes data it never got (core/test/tla/net, SN_sreconcile, TN_reconcile). Rule: each Pull carries a digest of S; a difference is repaired through Lost, and a Lost not caused by a credential change makes the member pending again.
> Priority: normal
> Tags: sync, node, proto, spec

S is a cache of the rule, but nothing compares the two sides' copies. Three ways to reach a divergence: a store restored to before an open (the requester holds a stream member the server does not), a connection dropped while a ByRole reply is in flight, a tester declining an accepted Hit whose beacon stopped being admissible (the acceptor keeps L open). In the first case the requester gets an empty reply, its stream cursor passes the member's events, and when the member opens later it is not a join: a silent gap (`SN_sreconcile`). In the others one side stays open forever (`TN_reconcile`).

## Rule
Each Pull carries a digest of the requester's stream members (a keyed XOR, O(1) bytes). On a difference the server sends its member list: a member the server does not share is answered as `Lost` with the Pull's cursor, so nothing is skipped; a member only the server has is offered. This is the same `Lost` as today, one mechanism for every cause. A member lost this way, with no credential change on either side, makes its credentials pending again on both sides, or the pair is stuck with nothing to test (`TN_retest`).

With the digest in place, re-sending `Lost` across connections is not needed for convergence (`T_remove` passes with it off). The `base` check is not shown to be: the model holds one credential per side, so additions cannot differ from the whole filter, and the digest compares S, not filters. issues/net-reconnect.md and issues/net-shared-set.md state the rule; the Message bytes are job 5's.
