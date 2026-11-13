# no-host-chain
- The failure read as a sync/convergence bug (a holder lacking commits) but was the sim's driver emulation reordering `Wake` actions; finding it took instrumenting node sync down to `next_wake`. The sim now checks after every node call that the held wake is the one asked (`NetSim::after_node`).
