# m1-whole
> Summary: Workflow snags met modelling the paths rule (roles-model `paths`, M1 brief 2).

- A 20,000-world `paths` run sits at the short lane's 115 CPU-s cap once a model's checks grow (each untrusting node judges every dispute candidate and a differential reading): a run that fit at the start of the task was stopped (exit 137) later with no change of size. Measure CPU-s (`/usr/bin/time`) after adding checks, before trusting `--short`.
- `Stats::print` shrank every failing property's first world on one core inside the hold, so a large control run would have held the heavy lock for its shrinks; it now shrinks only in runs of at most 20,000 worlds.
- Oracle drift: each new thief move needed several rounds of oracle fixes (what the thief's heard writes legitimately take, what a re-grant restores); the failures they produced looked like rule failures until traced. Tracing a shrunk world by a throwaway ignored probe test was the fast way.
