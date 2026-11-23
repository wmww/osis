# split-wake complaints
> Summary: footguns met fixing the split-path wake (order seed replays, probes).

- A passing test swallows `eprintln!` probes: a probe run that "prints nothing" needs `--nocapture`, else it reads as "never fired".
- The missed-wake panic names the waiting commit, not the transaction that moved its opener; finding it took probes after `f` and inside `reexamine`. Printing whether the wait is due (`Effects::current` None) up front would have said "drain missing, not dependency missing" at once.
