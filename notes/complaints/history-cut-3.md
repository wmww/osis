# history-cut-3 complaints
> Summary: Workflow snags met while updating Cut.tla for Tess's re-add decision.

- `run.sh` with `TLC_KEEP_LOGS` set to a missing directory failed its `cp` after the first instance and, under `set -e`, skipped the rest with exit 0 (fixed: it makes the directory).
- `run.sh` still makes its metadir with `mktemp -d` (tmpfs); set `TMPDIR` to a scratch dir to keep TLC state off /tmp.
- Each `tools/heavy` call waited 400-460 s for the lock behind other runs; the instances themselves took 1-200 s.
- The brief asked for `GoneFresh` to "become required", but it already was, and its old meaning (a removed member's new node opens nothing from before its removal) is what the decision gives up; it was redefined rather than kept.
- Review: a flaky store test merged on main (1 in 20) failed this TLA-only branch's gate; the gate's rebuild over main's new store commits cost 247 s of a 447 s gate.
