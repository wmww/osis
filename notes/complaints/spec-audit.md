# spec-audit
- Long single-line spec paragraphs (sync.md §5, commits.md §5) make exact-string edits and diffs hard to review; grep/sed context windows truncate them.
- tools/spec_map.py rule anchors are substrings of spec sentences: a wording fix to a MUST sentence must update RULES too (`--gaps` catches it).
- No way to block on subagents besides a background sleep plus claudewait.
