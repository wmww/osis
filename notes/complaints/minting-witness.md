# minting-witness
- `tools/policy.py` is not executable in a worktree checkout (Permission denied); run it as `python3 tools/policy.py`.
- A reader's minting in a node test needs its grant ingested after the net settles, else `commit_hostile` refuses ("a record on its chain is missing"); the forged-minting test's order is the one that works.
- A new deletion rule surfaced pre-existing duplicate header copies (two nodes placing the same minting in one round) as deletes in `deletion::reregistration_waits_and_sends_once_spec_sync_5`; duplicates stay, bounded per placing node.
- The gap-2 sequence did not fail as first written: `State::sweep_certs` (hourly) forgets a placement once the commit's bodies are gone, and any node that never placed the witness (r, b) places it at destruction anyway. The test needed every other placer away to reach the gap.
- Giving c Write on t through a group of a's made `net.advance` never return (fixed on writer-stall); lost time to it before checking main.
- A non-reader of a live thing never places its witness in the test net (its certificates do not carry the record), so no test reaches a label whose only placers are non-readers.
