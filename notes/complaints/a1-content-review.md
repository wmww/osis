# a1-content-review
> Summary: Mishaps met reviewing A1 step 3b (paths content and vouches).

- The differential's exclusions were applied only to failing worlds, but `open_17`'s predicate held in 38% of content worlds (7,592 of 20,000): any disagreement there was hidden. A predicate excusing a disagreement should be counted against the run (how many worlds it covers), not only the failures it excuses.
- A mutation table needs every OLD to occur once; a quick script that applies each, runs `paths::` and restores was enough (about 15 s per mutation on a warm target), cheaper than mutate.py's rows for multi-line sites.
