# reach-index-review
- A by-hand count over a sync world of six nodes (four member accounts to remove) takes about 70 s in debug: the world builder pairs and introduces every node; a member that only needs to exist as a holder (never syncs) still costs a full node.
- The worker's storage comparison ("about 1 KB today") was an estimate from the derivation alone; measuring today's first read showed the document already carries every writer removal (keysets' carried demotions). Storage claims about "today" need a run of today's engine, not the A2 model.
