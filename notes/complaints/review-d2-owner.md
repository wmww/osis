# Complaints: review-d2-owner
> Summary: Snags met reviewing and gating d2-owner.

- The branch redrew the story (two new thief moves) and moved the `counts:` baseline's numbers (dispute 12 to 4, README updated) without touching `tools/known_failures.txt` or the issue's count: a branch that redraws a baselined search should refresh the line itself, with the reason, so the reviewer only checks it.
