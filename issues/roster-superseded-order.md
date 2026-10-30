# A roster snapshot kept out as "superseded" depends on arrival order
> Summary: a roster snapshot whose linked tenure frontier blobs are missing is kept out of perm for good when the timeline at arrival already has a later epoch start; if that later start is dropped afterwards, nodes that got the snapshots in the other order use it as the start and these nodes do not: rosters differ for the same held set.
> Tags: security, engine, perm

Severity: low-medium (needs missing frontier blobs plus a later start's author being demoted).

Scenario: N has roster snapshots S1 < S2, S1 with a linked frontier whose blobs are not held. Node A gets S1 first (pends for blobs, `Reason::WaitBlobs`), then S2 and the blobs; node B gets S2 first, then S1 without blobs: `linked_frontiers_capped` (core/engine/src/apply/validity.rs:358-370) puts N in `superseded`, S1 applies, `add_membership_in` (validity.rs:467-470) never adds it to perm and nothing re-adds it. If S2's author is later demoted with a frontier not listing S2, A falls back to S1 and B to no start.

Spec: spec/permissions.md §5 (validity a function of held commits); §6 excludes only snapshots withheld as bad input or awaiting frontier blobs.

Fix direction: treat it as waiting whenever the blobs are missing (no superseded shortcut), or re-evaluate kept-out snapshots when that thing's epoch start changes.
