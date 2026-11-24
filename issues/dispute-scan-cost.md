# The dispute listing is capped in point order
> Summary: `disputes()` walks once per contestable removal (no exact filter exists: notes/disputes.md, Scan bound), so it examines at most `LIST_MAX` (64) candidates in point order and counts the rest; a flood of early-stamped hostile removals pushes a later open dispute with no recorded side past the cap, counted but not listed. The cap is no parameter of the API or CLI.
> Priority: low
> Tags: perm, api

Detection (engine `sides::after_update`) reads every open dispute, and every recorded side is listed whatever the cap; nothing hides silently (the count is reported). Options: a bound parameter (`disputes(max)`), or listing the recently flipped candidates first as detection does.
