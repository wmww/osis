# a1-spec
> Summary: Mishaps met while drafting the A1 spec text.

- Draft spec text in notes/ is checked by tools/doc_refs.py against the current spec: a cross-file pointer naming a section the draft itself introduces (e.g. commits §4 Received) fails, so drafts cite new sections by number only or put the name before the path.
- New grammar names in backticks (CamelCase with an inner capital, or with `_`) fail tools/code_refs.py until built: drafts use single-word names, or leave a planned constant out of backticks (an allow entry in tools/ takes the gate off its docs-only path).
