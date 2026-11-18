# gimbal-terms-code
- ugrep refuses `.{0,200}`-style context patterns ("exceeds complexity limits") and warns on `--exclude-dir` for paths given explicitly; Python was the reliable search and replace tool for a rename pass.
- Prose renames break line-wrapped phrases ("first\n// admin"): a line-based grep misses them; search across newlines.
- "under X" for a mint admin is everywhere in comments and has many other senses (under a sync ID, an epoch, a key); a full pass needs reading each, which this pass did only for "made under", "makes X under", "thing under".
- Review: a token-level diff (comments dropped, identifiers and string literals compared pairwise) proved the rename pure in seconds; difflib over whole-file token lists is fast only with precompiled regexes and `re.match(src, pos)`, not `src[i:]` slicing.
- The gate's first run met four failures that were main's, not the branch's (the app tile test and three engine properties at the gate's random seeds), none listed; each needed a main-binary replay (`tools/bin-at`) and a commit on main before landing. Main was not green on the properties at small size.
