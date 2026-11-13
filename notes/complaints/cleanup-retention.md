# cleanup-retention
> Summary: A dedup pass over retention/ found little duplicated logic left; most size is dense comments and real case logic, so safe merges saved about a hundred lines, not several hundred.

- Duplicates are mostly two- or three-line idioms. Turning each into a helper often saves nothing once the helper and its doc comment are counted (a `Right::of` constructor came out net +6 and was reverted). Count the lines before extracting.
- Larger cuts need design changes, not dedup. Example: issues/frontier-stop-below-purge.md, which removes a second rule for one property. That is out of scope for a pass that must not change behaviour.
- `claudewait` can't wait on Agent tasks, only on Bash background tasks ("unknown task ID"). Wait for the agent's notification instead.
- `tools/dead_pub.py` found nothing in this area.
