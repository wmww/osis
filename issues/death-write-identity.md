# A death names a stamp, not a write
> Summary: `osis_crdt::Death` carries the dead write's stamp, not its position, and a stamp names many writes, so `replaced_at` judges a snapshot's writes by counting one join's reports per stamp (`bounds::counts`); counts can match while the writes differ, dating a snapshot early.
> Priority: normal
> Tags: retention, crdt, engine

A snapshot's dating is per write (spec/commits.md §5: the latest death among the writes it carries that no later snapshot with at least its D carries). One write op stamps many writes (here every value of a map set shares one stamp), so `carried` and `snapshot_deaths` count reports per stamp, or per (stamp, killer), as a stand-in for which writes died. Two ways the stand-in can date early. Neither is reproduced yet:
- `carried`: snapshot C holds writes A1 and A2 of stamp s. Later snapshot L holds A1 and A3 of s: L's writer never saw the write that killed A3 before C, and it saw X, which killed A2. A root reset R then kills them all. C and L each report two deaths of (s, R), so C counts as carried for s, but nothing later keeps A2's history.
- one join reports a write twice (a record pair's cross death, spec/crdt.md §5.6; a text delete over an undelete), so in `snapshot_deaths` a stamp's count can be reached before all its writes are dead.

Direction: a death names its write by stamp and position (path and slot, per element in a range record). Dead writes become a set. `carried` becomes "some later snapshot's dead set has the write", and a snapshot dates at the latest of its writes' first deaths. Then `counts` goes. This threads a position through every crdt join and prune that reports a death. A study should first check that range records and records of one dot give the same position in every fragment.
