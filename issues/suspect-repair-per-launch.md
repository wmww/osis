# A suspect report that never settles costs a snapshot per writer launch
> Summary: `repair_state` is in memory, so a report that no snapshot can settle costs each writer one more snapshot per launch. The snapshot covers the last one, so bodies hold steady, but check the header left behind against the session growth rule (notes/growth.md). Found in the purge-flip review; not measured.
> Tags: node-sync, performance
