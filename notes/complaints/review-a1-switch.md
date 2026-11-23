# review-a1-switch
> Summary: Mishaps met reviewing the a1-switch branch.

- Old-walk remnants hid where a policy check cannot see them: prose in test comments ("the old walk's Acting check", "Interim in code"), a test comparing "old" and "new" walks that had silently become the engine against a walk afresh, and a scale counter left as a literal `0u64`. A remnant grep (`old walk|new walk|invite|Acting`) over `core/` caught them; worth a line in the switch brief.
- A sed rename (`invite` to `may-grant`) left "an may-grant" in eight places: renames that change a word's first sound need an article pass.
- No issue existed for the kept purge-author indexes, so their Interim sites had nothing to cite; the switch note listed them under Left only.
