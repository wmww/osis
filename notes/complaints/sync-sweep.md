# sync-sweep
- Shrinking a faulty differential seed is single-threaded and replays each candidate twice (determinism check): 46 steps took 363 s wall, close to the 600 CPU-s seed timeout (`OSIS_SEED_TIMEOUT_SECS`) that also covers the shrink. A longer history would be called hung mid-shrink.
- The shrunk script names the failure, not who diverges: telling sync's delivery from engine judgement took a throwaway probe (each node's reads, which handed commits each lacks, `history::hand` and read again). A failing check could print each node's reads and missing commit count.
