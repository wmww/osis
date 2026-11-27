# Tests failing since opening by entries landed
> Summary: 1 osis-sync test still fails since the entries design: a re-granted public not read.
> Priority: critical
> Tags: sync, engine, tests

Each is in tools/known_failures.txt against this issue.
- `differential::the_public_granted_again_is_read_again_*` (no quiet run between the public's removal and its re-grant): node 0 reads thing 1 (made in thing 0, made independent by a grant to node 0) and through it thing 0 by the public; after the public's revoke and re-grant on thing 0 it sees the public's read and the admin on thing 0 but reads no value of it. Not traced past that.
