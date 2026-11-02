# A write-only re-seal ignores read boxes' names
> Summary: `departures::sealers` counts only boxes to holder actor M of the roles the node seals. A re-seal of write alone skips M's read boxes, so names they carry (and that are met here) never free it: it stays bound to the edge's `keyset` (or leaves M out) when it could seal free.
> Tags: keys, security

Found in the grant-keyset review, not fixed there. Effect is liveness and keyset freshness (a bound write box seals to the older read-box commit's keysets, or M is left out of write until it rotates), not a leak: a bound seal is the conservative side.

Reviewer's suggestion: consider the boxes of every role at or below the highest sealed role (a write sealer holds read's secret, so it can open the read boxes' names), not only the sealed roles. Check that the lower box's names say what the higher one needs (a departure from write inside M the read granter knew).

Checked (pending-drops branch), not built: counting boxes of every role up to the highest sealed one is unsound as it stands. A sealer's departure names are role-independent, but its keyset names are not: each box names only M's keyset of that box's role (spec/crypto.md §4, `keyset_names`), and keyset names are what still binds where a roster snapshot of M hides a departure (`Held::keyset`: no epoch start stands in). A read box therefore says nothing about how fresh M's write keyset must be. Example: W demoted from write inside M before M's roster snapshot S; the read granter's names are {S, M's read keyset}; a node holding S and M's read keyset but an older `keys.0` write keyset of M (one W holds) would seal A's write free to that keyset and hand it to W. Today it stays bound or leaves M out, which is only liveness.

A sound version needs a lower box's names to vouch for the higher roles' keysets: e.g. every box to M names M's keyset epochs of every role the sealer holds for M (not only the box's role), then count boxes up to the highest sealed role. That changes what every grant, re-seal and rotation writes (spec/crypto.md §4, spec/wire.md §7): a design decision.
