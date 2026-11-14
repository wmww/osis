# created-items
- `wt claim` takes only origin/main; the preamble's "reset to sync-rebuild" step meant basing on a local branch (`minting-standin`) by hand, rebased later with `--onto`.
- spec_map's stray-anchor check wants the anchor to be literal section text; a paraphrased anchor fails `--gaps` only after the test is written.
