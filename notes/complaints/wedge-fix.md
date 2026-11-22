# wedge-fix
> Summary: footguns met setting aside faulting commits.

- A python `str.replace` of a match-arm line meant to append a new arm duplicated it onto the same line: scripted edits on one-line match arms need an exact before/after assert, not concatenation.
- `rg PATTERN | ...` with no path argument, in a call that went to the background, read stdin and hung (674 s) until stopped: always give rg a path.
