# retention-4
- The first tier-1 run in a worktree warm from another branch took 36 min (build ~28 min: node `it` alone ~10 min single-threaded rustc at load 25 beside a nice-19 sim-sweep and a TLA run). Later edit-test loops of engine + node + osis `it` took 4-5 min.
- `Engine::drop_body` used to drop any body (falling back to a non-covered drop); about ten tests leaned on that to fake drops the principle no longer allows. It now refuses an uncovered body, so such fakes fail loudly.
- Reviewer: each `tools/bin-at main` cost a rebuild there and another back (3-5 min each way); three old-vs-new probes spent about 20 min building.
- Decision changes mid-task (junk drop: never, then leftover, then never again) cost a stop-and-report round; check a decided rule against the value-less list invariant (it strips valid carriers' copies) before choosing the expiry leftover for anything new.
