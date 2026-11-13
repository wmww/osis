# purge-issues
- No way to see why a node lacks a part: diagnosing "d never holds x's record" took probes in `ingest_class` and `open_commit` to find the section stayed sealed. A debug env line naming sealed sections a node could not open, per commit, would have cut that to one run.
- Issue `purge-no-reset-older-value` pointed at "question 2B" in a note that no longer exists; recovering it took a git archaeology detour. Issues should cite durable places.
