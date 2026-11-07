# An invalid delta's arrival rebuilds its aspect
> Summary: An invalid delta is never joined: its arrival rebuilds its aspect from every held body (`join_part` adds it to `Joins::rebuild`, the one path of issues/drop-rejoin-robust.md item 1), and where a held body has a relative keep bound the rebuild marks deaths for a replay (`mark_if_bounded`, `replay_all`). So each forged write on an aspect costs O(held bodies) though it took nothing. A forged write can itself be that bound.
> Priority: low
> Tags: engine, retention, security

The forger needs a chain to the thing, not a right on it. Bodies a snapshot covers are gone, so this matters on an aspect that does not compact. Measured before the one rebuild path (debug build): 20 µs per small held body for the deaths replay alone (2000 bodies: 41 ms per arrival); not re-measured.

Possible fix: skip the rebuild when the state held no write under any of the arriving delta's dots before (nothing of it can be in the state, so the rebuild is a fixpoint and no death needs a date). That is a second path beside the rebuild, which drop-rejoin-robust avoids on purpose; worth it only with a measured cost, and the debug rebuild check (`check_rebuilt`) would cover it.
