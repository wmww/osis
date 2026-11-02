# A write-only re-seal ignores read boxes' names
> Summary: `departures::sealers` counts only boxes to holder actor M of the roles the node seals. A re-seal of write alone skips M's read boxes, so names they carry (and that are met here) never free it: it stays bound to the edge's `keyset` (or leaves M out) when it could seal free.
> Tags: keys, security

Found in the grant-keyset review, not fixed there. Effect is liveness and keyset freshness (a bound write box seals to the older read-box commit's keysets, or M is left out of write until it rotates), not a leak: a bound seal is the conservative side.

Reviewer's suggestion: consider the boxes of every role at or below the highest sealed role (a write sealer holds read's secret, so it can open the read boxes' names), not only the sealed roles. Check that the lower box's names say what the higher one needs (a departure from write inside M the read granter knew).
