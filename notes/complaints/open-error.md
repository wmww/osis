# open-error
- Dropping the last `Osis` handle leaves the store locked until the node's runtime shuts down: an immediate reopen fails "Database already open". Only `Osis::close` waits. Easy to miss in shells and tests.
- masonry's `Prose` exposes no text to the access tree, so tests reading labels can't see prose; walk the widgets and read `TextArea`/`Label` text instead.
- A heredoc edit followed by a stray `cat > /dev/null` hung a Bash call on stdin until TaskStop (my slip, but no hint from the tool).
