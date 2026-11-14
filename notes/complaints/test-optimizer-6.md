# test-optimizer-6
- `python3 tools/limits.py tests` runs every default test under the heavy lock (minutes); the brief lists it beside instant checks. Started it by mistake as a quick read; stopped it.
- pertest flagged `osis it runtime::a_paired_peer_serves_what_it_reads_in_process_spec_data_model_9` failing once at load (exit 101); it passes alone. A real-runtime test that flakes under load.
- pertest `compare` shows crdt-model and osis-keys props moving 7-8% between identical-product runs: their proptests draw fresh seeds per run, so they are noise in any before/after.
- Comparing sim per-seed counts for a harness change (e.g. one fewer `quiet` round) is not possible: the changed step changes every step after it.
