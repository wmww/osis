# Every rotation re-writes every departure name the actor ever had
> Summary: A rotation's history boxes name every departure from the actor its rotator holds (spec/crypto.md §4), with no reset point, so each rotation and each grant's or re-seal's copy carries O(departures ever): about 76 B each, 76 KB per history box per role at 1000 departures, O(departures²) over a chat's life.
> Tags: keys, performance

Nothing resets the list (nothing ever wrote the reset point the removed roster snapshots could have given). The spec/requirements.md Scale exception covers keeping role history, not re-writing it per rotation. Measured at small size in notes/crypto.md (Costs: a 10-reader group's read history box grows by about 112 B per removal). Options: name only departures after the newest epoch the rotator's history box supersedes and whose names are met (a reset point from the epoch chain itself), or accept it as part of the role-history exception and state it.
