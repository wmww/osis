# certs-index
- Started from a local merge of read-rejudge and grant-copies while they were in review; the integrator's merge differed (sync_holding dropped), so the rebase conflicted in the same Core field lists. Branches touching `Core`'s field list conflict every time.
- A publishing count test passed for nothing twice: the first world filed every new thing in D (closure reads short-circuit published), the second published under an account (no body of D's sync IDs). Only a mutation probe (the published view read whole) showed it; probe every new count test.
- `costs` cause names (`Effects` `<- container`) found every coarse read here in minutes; reading code did not.
- (review) A probe's `git commit -qam wip-probe` on a clean tree commits nothing, so the restore `git reset --hard HEAD~1` dropped the previous wip commit (recovered from the reflog). Restore with `git reset --hard HEAD` after a probe made on top of a committed wip, never `HEAD~1`.
