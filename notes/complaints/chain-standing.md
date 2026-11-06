# chain-standing
> Summary: worker complaints from the standing-chain fix and the seed-7300 oracle fix.

- `tools/policy.py` forbids dispute calls (`.disputes(`, `.choose(`) outside a short list, test harnesses included: a harness needing the walk's side must route through `core/node/tests/it/disputes.rs`. Found only at the instant checks; worth a line in notes/testing.md if it recurs.
- A Bash call piping a cargo test through `grep` moved to the background after 180 s under load 36 with no output (the pipe buffers): run tests into a log file and grep after.
- The inbox stamp/copy rule is reachable with a standing difference only in a window (a blob opened while the chain stood, judged after the cut): receivers already open inbox blobs by the standing chain (`inbox_actors`). The test needed an offline accept to hold that window open.
- Review: main moved (first-admin-d) during the gate; a second rebase hit conflicts in notes/permissions.md and two deleted issues, and the gate ran twice (432 s each at load ~16).
