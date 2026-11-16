# keel-workflow1
- notes/build.md described `wt release`'s build-key check as the plugin's (0.6.1+), but ostrich runs 0.6.0, which marks (three full builds) on every release: 310 releases in 3 days took 295 agent-minutes (median 49 s, 72 past the 120 s tool cap). Checked the installed plugin's source, not the note.
- `tools/agent-times.py` over the whole Fathom session (757 agents, 1.4 GB of transcripts) runs past the 120 s tool cap; pass `--since`.
