# perm-resnapshot
- osis-perm tier-2 set took 385-400 s per seed at load ~33 (notes say 2.4 min); three seeds ~20 min.
- World::fresh_id starts at 1001, so a hand-copied history using `cid(0x3ec)`-style IDs from a failure dump collides with the snapshot's fresh ID; offset copied IDs.
