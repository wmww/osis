# The dispute listing is capped in commit ID order
> Summary: Finding disputes walks once per contestable removal (no exact filter exists: notes/disputes.md, Scan bound); `Osis::disputes` lists at most `LIST_MAX` (64) open ones, the first in commit ID order (`Engine::disputes(max)`), and counts the rest; a flood of hostile removals (a removed admin can sign any number) pushes an open dispute with no recorded side past the cap, counted but not listed. The cap is no parameter of the `osis` API or CLI.
> Priority: low
> Tags: perm, api

Detection (engine `sides::after_update`) reads every open dispute, and every recorded side is listed whatever the cap; nothing hides silently (the count is reported). Options: the bound as a parameter of `Osis::disputes`, or listing the recently flipped candidates first as detection does.
