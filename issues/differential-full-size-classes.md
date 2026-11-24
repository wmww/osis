# Full-size sync differential: classes to check once it runs again
> Summary: `OSIS_FULL=1 differential::histories_hold_their_closure_plain` failed on a few seeds in 200 before the sync rewrite; whether any class still reproduces is unchecked, and the differential fails on every seed until accounts piece 7 (issues/accounts-properties-fail.md). Then run the 200 seeds and turn each class into a hand test: S's required set hanging on what a node holds by other paths, stale status sources.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes change: work from scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1`; run the 200 seeds as four `tools/heavy` holds of 50.

- **S's required set hangs on what a node holds by other paths.** Script: `New(3), NewIn(3, 0), Give(3, 1, Holder::Node(1), Syncs), Strong(1, None, 1), Strong(1, None, 0), Give(3, 0, Holder::Node(1), Reads), Run, Unstrong(0, Some(0), 1)`: Alice makes T0 and T1 minted with admin T0, grants Bob sync on T1 and read on T0, Bob holds both from his root, Alice drops T0 -> T1. Bob logged T1's keying must-hold under T0's sync ID after Alice released T1, against spec/sync-set.md §2 ("T's sync ID carries exactly T's sync unit"). Replay first: copies per (commit, thing) may have changed it.
- **Stale status sources**: "sources status counts that are no member at quiet", unshrunk.
- **A revoked store never reopened** (latent, no reproducer on main): after a revocation nothing reopens S at a store whose credentials and `changed_at(S)` did not move, so it is never tested again (spec/sync-opens.md §5 Testing) and keeps S's entries.
