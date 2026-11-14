# A listed thing's sync record keeps every sync secret a boxes payload brings
> Summary: A boxes payload not taken still gives a thing a synced closure lists its boxes' sync secrets (spec/sync-inbox.md §2 Taking), and nothing bounds or drops them: a forger knowing the tid and the recipient's inbox KEM key adds one useless epoch secret to the record per payload it gets deposited, kept for good.
> Priority: low
> Tags: security, sync, engine

- Harm: storage only. A forged secret names an epoch of the forger's (an epoch names its secret), which no step of a real sync ID bears; the node shows its sync key at opens (spec/sync-opens.md §4 shows the keys of secrets no step of its path bears), which reveals nothing.
- Rate: one per deposit the inbox's writers let in (the deposit budget, spec/sync-inbox.md §3), but the record keeps every one after the deposit is cleared.
- Options: drop a record secret once a step of the thing's path bears a later epoch's sync key (genuine secrets are superseded the same way); or keep listing-only secrets apart until a whole take or a step shows them.
