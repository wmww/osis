# sheave-c21-lower
- `grep -o`/`git grep -o` with a context pattern like `.{0,120}word.{0,80}` fails here ("exceeds complexity limits", grep is ugrep) or runs past the 120 s tool timeout on a big tree; cost a stalled call and reruns. A line in notes/build.md's footguns (use a short python filter for context snippets) would have saved it.
