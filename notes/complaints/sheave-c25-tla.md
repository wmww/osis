# sheave-c25-tla
> Summary: core/test/tla/run.sh died silently at the first cfg expected to fail that passed.

- run.sh (`set -euo pipefail`) printed a FAILED line for a negative control that passed, then exited: its `grep -E 'Error|violated' | head` found nothing, so the pipe failed and `set -e` ended the script before the remaining cfgs and the summary line. It read as a short run, not a failure list; I lost a rerun to it. Fixed with `|| true` on that pipe; a run.sh self-check (a dummy passing cfg expected to fail, then a second cfg) would have caught it.
