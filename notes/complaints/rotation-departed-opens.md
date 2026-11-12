# rotation-departed-opens
- The rotation property's "held, but no state met opens it" clause reads as a leak whenever `Run::states` misses a state: states were noted per step, so a box one write wrote and the next write of the same step removed (two hostile removals in a row) was invisible. A probe printing `ever`/`first`/`base` per epoch found it in minutes; worth keeping such a dump in the failure message.
- Bisecting the seed over older commits is moot for an oracle gap: the gap predates the recent rotation commits (the clause came with a663d3af5), which only change which histories a seed generates.
- The 400-seed sweep waited on the heavy lock behind another all-core run.
