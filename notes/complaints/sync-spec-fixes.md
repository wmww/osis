# sync-spec-fixes
- Test anchors were free text: 72 sync/wire citations named no rule (summaries, "by hand" markers, section titles). `spec_map.py --gaps` now fails on them; the other spec files still have 346 (issues/spec-anchors-rest.md).
- A member "closed here" test first used `table.set(S, None)`, which drops S from the record entirely (stops holding S), so it never exercised the Lost path: use a J departure to close a member while still holding S.
