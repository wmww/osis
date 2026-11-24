# Tool and harness fixes owed
> Summary: Fixes to test harnesses and tools that agents asked for and that are too large for a quick fix: failure messages and dumps that name what failed, quiet checks that miss stuck states, a shrinker that changes cause, a one-seed replay failing its floors, a safe library differential against main, per-node cost counts, and smaller tool gaps. Ordered by how much time each cost.
> Priority: low
> Tags: tests, tools

1. **Failure messages and dumps that name the cause.** Each cost one or more probe builds (an engine or sync rebuild is 1-5 minutes; one sync job spent a third of its time on `eprintln!` probes):
   - sync's quiet-check dumps and the rotation property's failing-history log name things by tid while the script names them by index: print both;
   - the order harness: name the failing check beside its text (`applied differs` was read as a walk disagreement for an hour), and a step-to-pack map (finding a step's pack means decoding headers);
   - `Engine::why_kept` says "goes when next judged (a pass end or a lost need)" for a thing waiting in `Core::pass_due`: name the queue; `why_role` could say why `Core::enter` took its context; a blob-to-sync-IDs dump beside `why_kept` (the storage-as-fresh tests name a leaked row, not who holds it);
   - the storm panic: the node ticked most and its last wake against the clock; the missed-wake panic: whether the wait is due (drain missing, not dependency missing);
   - `Effects` causes: the key, not only the table, and whether a moved read came from the settle's own rollback;
   - the sync trace: an entry that stays NotOpen shows `+entry` without `+commit` and nothing says why;
   - a held-in-part placement reports misses and bail-outs as bare bools;
   - a cost test (`thing_cost::what_a_reader_costs`) printing its rows by table on failure.
2. **Quiet checks that miss stuck states** (a test passed vacuously at half the seeds; a stale-read bug hid behind the second): a quiet end with a commit pending `WaitBlobs` on blobs a source shows; `World::parks` skipping store entries never opened.
3. **Library differential against main**: comparing a library crate's behaviour with main's (not a binary, so `tools/bin-at` does not help) is done by `git checkout origin/main -- <crate>/src` and back, which has dropped uncommitted edits and pulled in a newer sibling that did not build. A `tools/src-at REV <crate>` (wip-commit, swap the sources in at the merge base, build, swap back) would make it safe; until then wip-commit first and `git reset --hard` back.
4. **Per-node cost counts**: `osis_base::costs` is thread-local and `World` steps every node on one thread, so counts mix nodes; a `costs::count_by` keyed by the stepping node (set in `World::deliver`) and by caller would answer in one run what took a backtrace probe.
5. **`OSIS_SYNC_SHRINK` shrinks to any failure**: a seed failing one clause shrank to a script failing another. Keep candidates whose panic's first line matches the original's.
6. **A one-seed order replay fails its floors**: `OSIS_ORDER_SEED=<n>` on a passing seed exits 101 on `Seen::floors` (a floor needs more seeds than one run). Floors should hold to the seeds run, or a one-seed run skip them and say so.
7. **cpuprof by caller and inlined frame**: `cpuprof_report.py` filters by one frame and symbolizes with `--no-inlines`, so inlined walks fold into their callers; splitting a cost by caller (`--callers FN`, `--under FN`) or by innermost source line (`llvm-symbolizer --inlines`) took private scripts.
8. **Comment-only manifest edits select the whole gate**: gate_paths.py and test_select.py treat any root `Cargo.toml` or `.cargo/` change as build configuration (every crate plus the unification check, about 2000 CPU-s), even for a comment. Ignoring a diff whose changed lines are TOML comments or blank, in both, would fix it.
9. **A `rate:` line in tools/known_failures.txt is never flagged stale** (KNOWN-BUT-PASSED skips it): replay each `rate:` line's REPRO at the gate.
10. **run.sh negative controls**: a TLA instance expected to fail passes whatever it violates; a `fail:<Invariant>` expectation checked against TLC's `Invariant <name> is violated` line would pin it.
11. **code_refs does not check `source:` strings**: engine judgment scenarios cite roles-model test names as strings, so deleting a model test leaves a dangling citation.
12. **Generator census and a no-room knob**: which of a model's generators write a shape took a temporary panic in `World::put`; the sync harness has no knob holding pushes back, so a test cannot tell an at-once lost-access drop from release's pass wait.
13. **`osis_blob::verify_stamp` returns `Ok(false)` for a good stamp** (the bool says "role entry"): read once took it as "bad" and re-encrypted every body it should have relayed. An enum (`Stamp::{Role, Entry}`) would make the misreading impossible.

Seed-dependent fixtures (a fixture seed taken from an env var): issues/fixture-seed-luck.md.
