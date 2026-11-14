# A member removed, dropped and granted read again reads nothing
> Summary: With the lost-access drop wired into the driver, a sync holder raised to write, removed (it drops what it lost) and then granted read again holds the new grant but never reads the thing's content again: osis-sync `flows::a_member_granted_again_writing_before_it_takes_it_reads_it_spec_sync_inbox_2` (ignored under this issue).
> Priority: critical
> Tags: sync, engine, tests

Script: New(0), Write(0,0) v2, Grant(0,0,1,Syncs), Run, Grant(0,0,1,Writes), Remove(0,0,1), Run, Disk(1,3,Fail), Grant(0,0,1,Reads), Write(1,0). At the check node 1 holds both roles but reads none (reference v2). Passes on sync-rebuild, where nothing drops; fails from the commit that wires `Engine::role_duties` into the driver, with or without the modules restarting after the forget.

Likely: after the drop forgot thing 0, nothing makes sync fetch or open its entries again once the re-grant's boxes give the secrets back (spec/permissions.md §3 Lost access; spec/sync-judgement.md §3, the reload forgetting names). Check first whether node 1 opens the re-grant's `secrets.0` box (No secret taken back), then whether read re-opens the S entries it held before the forget. Fathom's "loss stands" rule (a node keeps syncing until a pass after the cause, then judges again) changes when the drop happens and may move this.
