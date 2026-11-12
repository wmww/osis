# minting-witness
- `tools/policy.py` is not executable in a worktree checkout (Permission denied); run it as `python3 tools/policy.py`.
- A reader's minting in a node test needs its grant ingested after the net settles, else `commit_hostile` refuses ("a record on its chain is missing"); the forged-minting test's order is the one that works.
- A new deletion rule surfaced pre-existing duplicate header copies (two nodes placing the same minting in one round) as deletes in `deletion::reregistration_waits_and_sends_once_spec_sync_5`; duplicates stay, bounded per placing node.
