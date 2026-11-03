# members-cost (tiller-members-cost)
- Callgrind on the sim costs 30-50x: a 40-member run took 25 min. `costs::span` counts per message in the bench found the real cause (passes per label) faster than the profile, whose `::name` lines (no generics, no debug info) were often ambiguous.
- `ls -t tasks/ | head -1` for "my newest background task" picks another agent's: the tasks directory is shared.
- `work_sets_*` with `--include-ignored` takes 15 min in a dev build: the oracle of any change to what marks a label dirty, so budget it.
- A foreground Bash build past 180 s is moved to the background without warning; the following command in the same line still ran.
