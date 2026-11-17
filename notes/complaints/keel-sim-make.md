# keel-sim-make
- `tools/cpuprof` sample counts vary a lot between runs on a busy box (the same 150 makes gave 1394 samples at n=100 and 1010 at n=400): compare shares scaled by `tools/icount`, never raw sample counts.
- Per-make icount needs two runs (k makes and 0 makes) since setup also grows with n; a probe test taking n and k from env made this easy.
- Debug-only whole checks (`misjudged`, `check_first_held`) are a large share of what a debug make costs at 400 held, and grow with n: easy to mistake for real growth.
