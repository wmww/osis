# node-open-changed (review)
- wt2's target was 16 GB of stacked generations at claim; `rm -rf target` and a 4 min cold build first. The gate then took 6 min, most of it clippy-net's first build in the fresh target.
- The `item_prefix` proptest's random-bytes branch almost never hits input that decodes, so it checks little. A throwaway mutation fuzz (flip a byte, truncate, pad: 300k cases) found nothing; it could replace that branch.
