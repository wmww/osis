# holds-departures-below
- `tools/heavy` waits were most of the wall time: each property run (about 150 s) queued 15-30 min behind gates; three heavy runs cost about 1.5 h of waiting.
- A plant run's seed list says nothing until each failing seed is replayed unplanted: two of the first plant "catches" were checker false failures that also failed unplanted. Run unplanted and planted over the same seeds in one heavy hold.
- Main moved under the branch mid-task (role sync), so every plant/sweep before the rebase had to be redone.
