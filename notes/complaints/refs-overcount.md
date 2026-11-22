# refs-overcount
> Summary: Footguns met fixing the reference index's set overcount.

- The known-references property has no shrinker (the brief and issue assumed one): a TRACE print per step and delivery, then a hand-written two-commit test, found it in minutes. A step log on failure would make that free.
- `Reference.count` is engine bookkeeping no user sees; only the property's count comparison caught the overcount (presence was always right).
- A first fix widening a set's reach to every equal value (not only those holding references) broke `scale::kept_snapshots_stay_within_their_window_spec_commits_5`: `state_part_at` of a snapshot body then reads the value index once per element. The default tests catch it; the crdt model alone does not.
