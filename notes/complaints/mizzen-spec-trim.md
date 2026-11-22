# mizzen-spec-trim
- Test anchors quote "so ..." consequence clauses (crdt §8 "pages are joined independently", §4.8 "the order of arrival does not matter", §6.1's sibling-order parenthetical, sync-ids §5 "the store is the truth for ciphertext"), so a spec trim can't tell rationale from a tested property until `tools/policy.py` fails. Cheap and safe, but a trimmer must run policy after every file.
- `cat` of a large spec file overflows the tool output (persisted to a file to Read again): read spec files with `sed -n` ranges from the start.
