# no-host-chain
- The failure read as a sync/convergence bug (a holder lacking commits) but was the sim's driver emulation reordering `Wake` actions; finding it took instrumenting node sync down to `next_wake`. A sim-side check that the held wake equals the node's last asked one would have named it at once.
- The issue file and its known_failures line lived only on `cleanup-label`, not main, so there was nothing to delete here.
