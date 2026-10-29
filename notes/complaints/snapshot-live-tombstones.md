# snapshot-live-tombstones
> Summary: footguns met on this branch.

- `retention::deaths_never_early_random_*` prints nothing with `--nocapture`: a run with `OSIS_STRAYS_SEEDS=3000` is confirmed only by its wall time (127 s against about 1 s for the default 24). Printing the seed range, as walks does in its replay hint, would make a misspelled env var visible.
