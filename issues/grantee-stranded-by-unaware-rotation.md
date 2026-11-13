# A rotation made before its rotator held a grant strands the grantee
> Summary: a grantee left out of a rotation whose rotator had not yet learned its grant never reads anything new of the thing, even with every node online for good: the rotator's later re-seal of it is wrapped under the epoch it lacks and never reaches it. Root cause unconfirmed.
> Priority: critical
> Tags: keys, engine, node-sync

A granted member that reads nothing new, for good, after an ordinary offline/online sequence: no unbounded stall is acceptable (spec/requirements.md). Independent of the derived-write merge (same result with `Engine::note_sealed` a no-op).

Reproduce (osis-node `Net`, `hosted_nodes::<4>()`, nodes f0, f1, t1, x):
- `f = net.group(f0, &[(f1, Admin), (x, Read)], &[host])`; `t = net.item(f0, f, f, "first")` (plain); `net.run()`.
- `net.set_online(f1, false)`; `net.pair(t1, f0)`; `net.grant(f0, t, tid(t1), Read)` (T gets secrets of its own); `net.pair(f0, t1)`; `run`, 3 × `advance(15_000)`: t1 reads "first".
- f1, offline, demotes x from F (`engine.demote` + `carry_out` + `actions`).
- f0 offline, f1 online, 20 × (`run`, `advance(15_000)`); `net.write(f1, t, "after")`, 20 rounds more: f1 reads "after", t1 "first".
- f0 online, 30 rounds; f1 writes "later", f0 "later0", 30 rounds: f0 and f1 read "later0", t1 still "first".

What happens (from the worker's prints): f1's first pass of T's label opens the own-secrets rotation (boxed to F) and, F's box being stale, f1 re-keys T at once, before it holds f0's grant to t1 (that entry is wrapped under the epoch it just learned). Its rotation boxes F only. Once f1 learns the grant it re-seals t1 at its new epoch, in a commit wrapped under that same epoch (the newest current one), which t1 cannot open; that commit never reaches t1 otherwise (its inbox delivery, `flows::edges::deliver_to`, lands nowhere it reads, or is never made). With f0 online, f0's re-key forks with f1's, and f0's re-seal of t1 at f1's branch strands it alike.

To find out: whether t1 counts as stranded there (spec/permissions.md §4) and sends a Stranded message or notice, and why the inbox copy of the re-seal never arrives (harness: no inbox at t1's account, or the engine). A pass-end rotation made before every entry of the pass was opened may also be early (spec/permissions.md §3 "complete pass"). The fix lands with the repro as a default test.
