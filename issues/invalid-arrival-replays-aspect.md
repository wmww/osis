# An invalid delta's arrival rebuilds its aspect
> Summary: An invalid delta is never joined: its arrival rebuilds its aspect from every held body (`join_part` adds it to `Joins::rebuild`, the one path of issues/drop-rejoin-robust.md item 1), and where a held body has a relative keep bound the rebuild marks deaths for a replay (`mark_if_bounded`, `replay_all`). So each forged write on an aspect costs O(held bodies) though it took nothing. A forged write can itself be that bound.
> Priority: low
> Tags: engine, retention, security

The forger needs a chain to the thing, not a right on it. Bodies a snapshot covers are gone, so this matters on an aspect that does not compact. Repro: osis-node `scale::repro_invalid_arrival_is_flat` (`rebuild: body` 61 -> 601 at 30 -> 300 held commits).

Possible fix: skip the rebuild on an invalid arrival. An invalid delta removes only its own writes (spec/crdt.md §4.6) and never joined, so its arrival cannot change the state: the rebuild is a fixpoint, and the debug rebuild check (`check_rebuilt`) would confirm it. Check first that no other change rides on that rebuild (a held commit's validity flipping in the same step, e.g. an overlapping session range voiding both commits, must still rebuild through `rejudged`).
