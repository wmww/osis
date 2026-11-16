# keel-kept-close
- The KNOWN failure for the emptied-request test was filed against the kept-unread issue but had its own open tess-call issue (destroyed-sync-id-never-left) on the same question; known_failures.txt lines point at one issue, so the second was easy to miss. Grep the test name across issues/ and notes/ before studying a KNOWN failure.
- `Closure::ticket_ids` (by sync ID) is cleared when a thing's last vertex drops and set again at its next judgement, so it does not say "a held ticket names S" for a thing kept out of the closure; that needed its own index (`node/refs ticket ids`).
- A rebase merged tools/known_failures.txt by union with no conflict: my removal survived but the stale seed-6 line came back beside main's new one. Diff it against origin/main after every rebase.
