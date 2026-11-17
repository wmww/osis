# keel-page-cache
> Summary: Mishaps met on the page-cache branch.

- The brief's premise (paged state decoded again drives per-make growth) came from the issue's own guess; counting `state page load` per make (flat) and gating the two debug whole checks settled it in minutes. Count before briefing a build.
- `tools/cpuprof` sample totals for the same work differed 1.3-2.4x between runs at different held sizes (CPU-time sampling on a loaded box): only shares within a run scaled by `tools/icount` are usable, and rows still move about 1 M between runs.
- `cpuprof_report.py` re-symbolizes the whole sample file on every call (about 20 s each); filtering several names means symbolizing once and grepping.
