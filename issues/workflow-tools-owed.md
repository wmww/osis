# Tool and harness fixes owed
> Summary: Fixes to test harnesses and tools that agents asked for and that are too large for a quick fix: failure messages and dumps that name what failed, quiet checks that miss stuck states, a generator census. Ordered by how much time each cost.
> Priority: low
> Tags: tests, tools

1. **Failure messages and dumps that name the cause.** Each cost one or more probe builds (an engine or sync rebuild is 1-5 minutes; one sync job spent a third of its time on `eprintln!` probes):
   - sync's quiet-check dumps and the rotation property's failing-history log name things by tid while the script names them by index: print both;
   - the order harness: name the failing check beside its text (`applied differs` was read as a walk disagreement for an hour), and a step-to-pack map (finding a step's pack means decoding headers);
   - `Engine::why_role` could say why `Core::enter` took its context; a blob-to-sync-IDs dump beside `why_kept` (the storage-as-fresh tests name a leaked row, not who holds it);
   - the missed-wake panic: whether the wait is due (drain missing, not dependency missing);
   - `Effects` causes: the key, not only the table, and whether a moved read came from the settle's own rollback;
   - the sync trace: an entry that stays NotOpen shows `+entry` without `+commit` and nothing says why;
   - a held-in-part placement reports misses and bail-outs as bare bools.
2. **Quiet checks that miss stuck states** (a test passed vacuously at half the seeds; a stale-read bug hid behind the second): a quiet end with a commit pending `WaitBlobs` on blobs a source shows; `World::parks` skipping store entries never opened.
3. **Generator census and a no-room knob**: which of a model's generators write a shape took a temporary panic in `World::put`; the sync harness has no knob holding pushes back, so a test cannot tell an at-once lost-access drop from release's pass wait.

Seed-dependent fixtures (a fixture seed taken from an env var): issues/fixture-seed-luck.md.

- **Landing after main fixes a gate's failures**: a gate's NEW failures fixed by commits main gained during the gate leave `merge-branch land` refusing (the rebased branch is no descendant of the gated commit); a reviewer reset to the gated commit and cherry-picked. Wanted: land rebases, reruns the failing tests by name on the rebased tree, and lands when they pass (or a documented `--rebased` path).
