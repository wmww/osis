# policy-citations
- `tools/policy.py` runs every check at import, so its checks could not be unit-tested; doc_refs moved to its own module (`tools/doc_refs.py`) to get a test file.
- A spec_map anchor (`spec/x.md §N (anchor)`) and a section name share one syntax; capitalised anchors had to be real leads of §N or reworded. Lowercase parentheses stay free text.
- `ugrep` (as `grep`) refuses `-oE` patterns with `.{0,150}` bounds around non-ASCII text ("exceeds complexity limits"); a short Python script was the way to print citation context.
