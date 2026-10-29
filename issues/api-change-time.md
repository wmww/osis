# No trustworthy "last changed" time for a thing
> Summary: A commit's `ts` is the author's clock, so a device whose clock runs ahead dates edits into the future; the app shows "Edited ..." from `min(ts, received)` of the newest content commit (filtering out membership commits by kind). Ask: a core notion of a thing's last content change with a defined clock rule.
> Tags: core-ask, api

Repro: app/src/data.rs `changed`.
Ask: `last_changed(t)` (content changes only, not placement/sharing), with the skew rule decided once in core (for sorting "recent" too).
