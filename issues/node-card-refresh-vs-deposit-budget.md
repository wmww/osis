# Node-card refresh cadence vs deposit budget
> Summary: The all-nodes predicate (notes/ephemeral.md) relies on nodes re-placing their node card under each label at a low rate; a reader's re-put is a deposit, so readers times cadence must fit the per-label deposit budget, which the spec does not size.
> Tags: sync

spec/permissions.md §4 now permits periodic re-placement as local policy. Open: the budget size (spec/sync.md §5 says "budgeted per label by count and bytes" without numbers) and whether a writer's promotion of node cards is routine enough to keep readers' re-puts from crowding out invite grants and self-removals. Either fix the cadence and budget as format constants, or drop the "last sync of L" reading of the predicate and keep only membership.
