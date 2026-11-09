# kestrel-docs-cleanup2
> Summary: a 15-minute budget covers one 130 KB note's implementation section, not the six big notes listed.

- notes/permissions.md is 43k tokens: Read refuses it whole, and its implementation section alone took the whole budget. Big-note cleanups need one agent per file.
- `grep -o` with a wide `.{n}` context fails under ugrep's complexity limit; `awk substr` works.
