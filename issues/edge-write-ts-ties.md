# Edge writes at one `ts` ordered by tid
> Summary: Two concurrent edge writes on one edge at the same `ts` (one admin grants, another removes) resolve by author tid; is that the edge's register order or an incidental tid dependence like the one layer 2 dropped?
> Priority: low
> Tags: permissions, tess-call

The role timeline orders edge writes by (`ts`, author, commit ID) (spec/permissions.md §5.1). At one `ts` the HLC proves two commits concurrent (spec/crdt.md §2.2), so the tid decides between writes neither author knew of. Layer 2 no longer lets that decide anything (§5.2 Position, notes/permissions.md Revocation).

Where the tid matters among edge writes:
- A demotion and the demoted's own edge write at one `ts`: no. Ordered first, the demotion makes the write not apply; ordered second, it audits the write (not in its frontier) and drops it. Same result either way.
- Two admins writing one edge at one `ts` (Alice grants Bob write, Carol removes Bob): yes. The later by tid stands. At different `ts` the later `ts` stands, which is the writers' clocks deciding between concurrent writes just as arbitrarily.

Options:
- (a) Keep: the key order is the edge's register order, as a content register's ties go by the dot's author (spec/crdt.md §2.2). Every node agrees; no rule outside the walk depends on it.
- (b) A tie at one `ts` on one edge goes to the lower value (removal over grant): tid-free for exact ties, but a special case, and clock order still decides one millisecond apart.
- (c) Treat concurrent conflicting admin writes as a dispute (§5.1 Trust set): heavy for a register conflict.

Recommendation: (a). The layer-2 case differed in kind: the tid decided whether a rule (addenda) could apply at all, not which of two writes wins.
