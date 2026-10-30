# A removed admin of actor X can backdate removals of X's edges, never audited
> Summary: a lowering of X's edge by an admin of X with no other authority on the target is a self-removal, and self-removals are never added to D; so a device removed from person P (properly, with a frontier) can write removals of P's edges on every shared thing stamped before its own removal, and they stand: P loses access until each admin re-grants, its gap edge writes stay dropped.
> Tags: security, perm, spec, owner-call

Severity: medium (spec-level; code matches spec).

Scenario: D is an admin of person actor P; P has edges on documents T1..Tn. An admin removes D from P with a frontier. D then writes removals of P's edge on each Ti with `ts` before its removal. `judge` (core/perm/src/walk.rs:1976-1983) classifies each as a self-removal (D is admin of member P, no authority on Ti); spec/permissions.md §5.1 step 4 "Self-removals are never added to D". The removal's frontier cannot drop them.

The rationale for never auditing self-removals (a later demotion would hand back what one gave up) holds for lowering one's own edge (`m == a`), not for an edge lowered through admin of the member.

Fix direction (spec change): only own-edge lowerings are immune; a lowering through admin of X is attributed to that admin-of-X standing and audited by a later demotion of the author from X like other writes, by its frontier.
