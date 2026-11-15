# Read's per-event judgement count depends on interleaving
> Summary: osis-sync `read::an_event_on_one_sync_id_judges_what_it_moved` asserts equal judgement counts at n=2 and n=20, but the count alternates 136/140 with n on the base too (an extra `bodies` settle when a commit's certificate rows land after its first settle), so it passes or fails by which sizes it picks.
> Priority: normal
> Tags: sync, tests

- Counts of `judged_per_event(n)` (read: judged, read: toward), base 483d21c90: n=1 136, 2 140, 3 136, 5 136, 8 136, 20 140, 30 140; with the certificate rule (cert-rule branch): n=2 140, n=20 136. "toward" stays 20. The 4 extra judgements are one more `read: bodies` settle of the grant commit moved by `Certified::naming` (its certificate rows written in a later `Engine::follow` than its first settle), re-judging it at 4 (S, commit) pairs. Not a growth with n, but the test reads it as one: it passes or fails by which sizes it picks. Find why the rows are not current at the commit's first settle (the `Chain` piece's timeline read moving a round later), or measure something the race does not move.
