# import-dots
- Tier 1 took 801 s at load 32-40 (notes say about 40 s warm); most of it waiting on other agents' load.
- `LocalPeer::sync_all` errors out when one peer refuses a bad commit, so a test of receiver refusal must deliver the remaining packages by hand.
- `wt`/`claudewait` still not on PATH in subagent shells; used the plugin cache paths.
