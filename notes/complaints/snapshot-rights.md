# snapshot-rights
- fbc12a15c (thing-history step 3) does not build alone (`Core::test_copy` misses `settings_due`), so a bisect across history-3 needs a one-line patch there.
- 1463b1fea is no baseline for `snapshot_rights` bound 2: before step 3 the scenario's purge-on-replace setting did nothing, so storage and cover counts there compare against a run without purge on replace.
- The sim's state bound reads backend units, not tables: finding what a node stores beyond what it must hold needed an ad hoc probe over `ix.commits` (held vs at host, by kind).
