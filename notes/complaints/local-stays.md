# local-stays
- spec_map lowercases citation anchors but compares RULES anchors as written: a RULES entry with a capital letter is never matched ("no test or issue" though tests cite it).
- "Carried" is easy to get wrong in engine tests: the account's synced group has no sync ID, so a plain thing listed under it (not under D) is carried by nothing; the harness's `people()` D has no `sync.0` either.
