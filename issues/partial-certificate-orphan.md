# A lost redeemer's partial certificate set leaves a commit pending forever
> Summary: sim `link_race` seeds 41, 107, 120, 144, 197 (200-seed sweep) fail "commits pending at quiescence": the losing redeemer's connection drops after one of its certificate-copy deposits under K's label lands, it is rotated out before it can re-deposit the rest, the admin promotes the lone copy, and the winner holds that commit pending `MissingChain` for good. Present with or without the stranded_reseal 23 fix.
> Tags: sync, permissions, tests

Replay: `osis_sim::replay("link_race", 41)` (`OSIS_SIM_TRACE=1 OSIS_TRACE_UPLOADS=1`).

Seed 41: the loser x (node 1) deposits its person creation commit's certificate copies under K's label as separate projections (`[4wgq/keys]`, `[uE6I/created 4wgq/created]`, the commit is in commit form with several reader actors). Only `[4wgq/keys]` lands before the link is cut. K rotates without x (its grant is invalid), so x's claims are refused and it cannot deposit again. The admin, which applied the commit from elsewhere, promotes the lone copy. The winner y (node 2) opens it, cannot verify the author (`uE6I` chain parts are not under the label) and keeps it pending (spec/permissions.md §4: pending until the chain arrives). Nothing in the spec obliges anyone to complete or remove it: the chain is its author's to place, and a certificate blob whose author has nothing else under the label is may-hold.

Likely directions (needs a spec decision):
- A writer promotes a certificate deposit only when the author's chain for it is under the label (or places the missing parts itself, since it holds the commit).
- Or: a certificate copy of a commit whose author is no longer a member and whose chain is incomplete under the label is outside the required set (must-not-hold), so admins delete it.
- Or: the sim invariant accepts pending commits by excused nodes' actors (only if the spec says such leftovers are harmless).
