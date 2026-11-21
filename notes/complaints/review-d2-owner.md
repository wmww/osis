# Complaints: review-d2-owner
> Summary: Snags met reviewing and gating d2-owner.

- The branch redrew the story (two new thief moves) and moved the `counts:` baseline's numbers (dispute 12 to 4, README updated) without touching `tools/known_failures.txt` or the issue's count: a branch that redraws a baselined search should refresh the line itself, with the reason, so the reviewer only checks it.
- The gate's only NEW failures were osis-perm's `paths_story_agree_plain`/`_large`: they draw roles-model's story, so new story moves (54, 55: a made-up owner key, which the old walk lacks) broke a differential in another crate. A roles-model change to the story or tiny generators needs osis-perm's `paths_*_agree_plain` run too, not just `cargo test -p roles-model`.
