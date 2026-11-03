# move-copy
- Box at load 35-40: tier 1 took 13 min wall, a two-test `-p osis-node` rebuild 4-5 min.
- Brief cited spec/permissions.md §8 for snapshot rules; §8 is purge rights (snapshot validity is §5.2).
- Created the scratch log dir in a separate call from the background run that wrote into it; the run raced it and failed silently (exit printed 0 from the redirect error).
- Review: local main lagged origin (needed `git fetch && git rebase origin/main`); load 35-45, a two-test `-p osis-node` rebuild 7 min.
