# fathom-code-refs
- `grep` here is ugrep: `grep -o ".\{0,160\}name.\{0,100\}"` fails "exceeds complexity limits" per line, and a loop of them ran past the 120 s tool limit. Use python for context slices.
- Notes cite tests without their `_spec_...` tail; any name check must strip it (tools/code_refs.py does).
