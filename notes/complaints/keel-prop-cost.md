# keel-prop-cost
- The recorded engine property costs were stale: custody measured 2,590 G (about 830 CPU-s) at seeds from 0, not 137 CPU-s; measure all 12 before ranking.
- A first node key printed store rows with `{:?}` and cost more than the checks it skipped (formatting `Vec<u8>` was 93% of it): hash, never print, on hot test paths.
- Planted wake losses (every `Wake::Commit`, then the commit and thing wakes too) failed nothing in `held_set_decides` with its per-ingest `lost_wakes` scan; the commit wakes alone failed no engine `it` test at all.
