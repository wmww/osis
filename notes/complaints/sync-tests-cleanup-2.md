# sync-tests-cleanup-2
> Summary: The plant issue named the wrong gap (both opens plants fail six `Pair` tests; the product memo plant is what survives), and the cleanup's line target met mostly distinct unit tests.

- issues/opens-standing-plant-survives.md said its two plants survive every osis-sync test; filtered to four world tests they do, but six `opens::` `Pair` tests fail on each. Run a plant over the whole binary before writing "survives everything" in an issue.
- A world test meant to isolate a J-only change kept passing under every plant: a sync grant's `until` passing also moves the judging node's credentials of S, and a read grant's leaves the member admissible (its epoch covers the departure). Probing `Opens::work()` and `member_at` beside `Engine::judge_peer`/`covers_departures` in a scratch copy of the test showed which path judged it in two runs; read those before building more world setups.
- The big modules' tests are mostly distinct `Pair`/`W` unit tests: near-identical pairs to merge into tables are rare; most of the line savings are repeated setups (`one_unread`, `Pair::read_one`, `reader_pair`, `crossed`, `two_shown`).
