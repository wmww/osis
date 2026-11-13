# A rotation made before its rotator held a grant strands the grantee
> Summary: unconfirmed root cause: in an osis-node `Net` run, a grantee left out of a rotation whose rotator had not yet learned its grant never gets the re-seal that rotator writes once it learns it (wrapped under the epoch the grantee lacks; its inbox delivery never lands), so it reads nothing new of the thing for good.
> Priority: normal
> Tags: keys, engine, node-sync

Seen while building the derived-write merge (spec/crypto.md §4 Current), but it does not depend on it: the same state arises with that rule switched off.

Reproduce (osis-node `Net`, `hosted_nodes::<4>()`, nodes f0, f1, t1, x): `net.group(f0, [(f1, Admin), (x, Read)])` is F; f0 writes thing T under F (`net.item(f0, f, f, ..)`, plain), `net.run()`. f1 goes offline. f0 grants t1 read on T (T gets secrets of its own), `net.run()`; t1 reads T. Offline, f1 demotes x from F (a rotation of F). f0 goes offline, f1 online, then 20 rounds of `run` + `advance(15_000)`.

What happens: f1's first pass of T's label opens the own-secrets rotation (boxed to F) and, F's box being stale, f1 re-keys T at once, before it holds f0's grant to t1 (that entry is wrapped under the epoch it just learned). Its rotation boxes F only. Once f1 learns the grant it re-seals t1 at its new epoch, in a commit wrapped under that same epoch (the newest current one), which t1 cannot open; that commit never reaches t1 otherwise (its inbox delivery, `flows::edges::deliver_to`, lands nowhere it reads, or is never made). t1 ends with a current read epoch it holds no secret of, and reads nothing written since. With f0 online too, f0's own re-key forks with f1's, and f0's re-seal of t1 at f1's branch strands it alike.

To find out: whether t1 counts as stranded there (spec/permissions.md §4) and sends a Stranded message or notice, and why the inbox copy of the re-seal never arrives (harness: no inbox at t1's account, or the engine). A pass-end rotation made before every entry of the pass was opened may also be early (spec/permissions.md §3 "complete pass").
