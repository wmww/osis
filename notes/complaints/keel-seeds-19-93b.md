# keel-seeds-19-93b
- The issue's seed 93 class had no script (only "40 steps, shrink cut short"): with no reproducer and no failing seed at today's bytes it could not be traced. Issues should carry the shrunk script whenever one exists, even partial.
- Seed classes moved worlds: the seed-19 script failed on 20 of 80 other world seeds at full size, which was the fastest way back to a reproduction (`differential::holds(seed, &script, ..)` over a seed range in a scratch test, one process per 5 seeds).
- A full-size replay of one seed is about 30-60 CPU-s; the end check `boxes_to` (index rebuild) caught a regression of mine that every default test missed.
