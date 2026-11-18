# gimbal-terms-spec
> Summary: A spec-only rename pass cannot stay docs-only: test citations and spec_map RULES quote spec text.
- Renaming spec words (first admin, plain, own keys) breaks `tools/spec_map.py --gaps`: test citation comments quote the old text as anchors, and RULES substrings must match spec sentences. Fixing them touches tools/ and .rs comments, which sends the branch to the full gate. A spec rename pass should be briefed with its citation sweep, or with the gate run budgeted.
