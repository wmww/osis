# mid-cleanup
- `wt` was not on PATH in this session (brief gave the plugin bin path); CLAUDE.md says to stop and ask in that case, the brief's workaround worked.
- perl lookbehind `(?<![\w.:])uint\(` for mechanical call-site rewrites also hit `fn uint(` (space before): exclude definitions explicitly.
- gate took 490 s at load ~40 (an osis-base change rebuilds the whole tree).
