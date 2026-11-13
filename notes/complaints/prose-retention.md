# prose-retention
- The prose-editor brief says `python3 tools/spec_map.py --gaps --uncited`; the tool takes one flag per run (usage error otherwise).
- 13 places in code comments and held-model cite note sections by name ("engine-retention.md Replaced (When)"); a split means a regex pass over code too. Section citations in comments rot silently: nothing checks them.
- Rebasing a split note over a branch that edited the old one: the conflict is the whole old file; carry the delta by hand (here one rename, clock_keep to at_clock).
