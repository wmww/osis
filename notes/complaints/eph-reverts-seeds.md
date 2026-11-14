# eph-reverts-seeds
- A first background command put `mkdir` after the redirect into the dir it creates: the run failed silently with exit 0 (my slip; mkdir first).
- Hand-built scenarios did not reach seed 960857231402's interleaving (role commits refused until a step registers, a placement again logged before them); only transcribing the seed's ops into a script and dropping ops one at a time (greedy, about 10 runs) found a small deterministic reproducer. A harness switch to make a host refuse a node's stamps for a while would make such tests direct.
- `OSIS_SYNC_TRACE` prints 300-char frames; finding one blob's story meant grep/awk over 1000+ lines. A filter by blob or commit ID in the harness would help.
- Review: the rebase onto main auto-merged tools/known_failures.txt wrongly (kept the fixed seed's line and re-added a line main had dropped) with no conflict shown; only the `git diff origin/main` check caught it.
