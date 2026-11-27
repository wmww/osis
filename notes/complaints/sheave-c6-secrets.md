# sheave-c6-secrets
- The index check's diff shows ~1200 bytes around the first differing byte of a table's `Debug`; a `secrets` diff needs the whole entry of the thing that differs (bumped `SHOWN` by hand). Showing the differing key's whole entry would have saved a round.
- Moving a cli failure to an engine test took most of the job: the cli node follows a thing through a grant signal its sync layer redeems, which no engine harness call gives; I set `followed_links` by hand. A `LocalPeer` helper that redeems held grant signals as the sync layer does would make such cases cheap.
