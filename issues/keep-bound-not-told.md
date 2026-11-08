# A part leaving the listing at its keep bound is not told
> Summary: A commit listener is not told when a value aspect's replaced part passes its keep bound (`keep_history(D)`, an `until`) and so leaves the listing: no timer runs then, the body stays until compaction drops it (told then, as dropped), and a later write is judged against a listing that already left it out. A page read shows it. Signals are told (their bound is a timer that drops the body).
> Priority: normal
> Tags: engine, api

notes/listener-design.md: one call per commit whose listed form reads otherwise. Seen: keep_day aspect, write a then b, listener on it, advance 2 days: `a` is no longer listed, no event, nor on a later write of the aspect.

Options: a timer at each replaced kept part's keep bound for aspects with a commit listener (the bound is `body_keep`, known once the part is replaced; in memory, as listeners are), naming the commit when it runs; or drop a replaced value body at its bound as a signal's is (a retention change: compaction is the only drop besides expiry and purge today).
