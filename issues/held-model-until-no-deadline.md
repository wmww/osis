# Held model: a fate leaves Keep(Until) with no deadline listed
> Summary: `props::settled_histories_keep_their_laws_large_spec_commits_5` fails on main at `OSIS_HELD_START=387315248891`: an invalid commit's part (196904) is `Keep(Until)` now and `MayDrop(PastBound)` halfway to the first deadline, which `deadlines` does not list, so `changes_only_at_deadlines` fails.
> Priority: normal
> Tags: held-model, tests

Repro: `OSIS_HELD_START=387315248891 cargo test -p held-model --test it -- --ignored settled_histories_keep_their_laws_large_spec_commits_5`. Either the held model (core/test/held-model/src/model.rs) misses the deadline at which an invalid part's `Until` keep ends, or the fate changes where it should not; find which side is wrong before fixing (the engine mirrors the model, notes/engine-retention*.md).
