# The invite-grant `/secrets` exemption fires on any applied op of the commit
> Summary: `valid_on` waives the role check on a membership commit's `/secrets` delta when any op of the commit on that thing applied and the boxes fit the edges the commit puts, applied or not; a self-removal always applies, so a reader or former direct member can pair a self-removal with a failing put for Z and get arbitrary boxes for Z and history boxes accepted.
> Tags: security, engine, perm

Severity: medium.

Scenario: R once held (or holds) a direct edge on T (its entry key is known, so a reset names it). R writes one membership commit on T: a reset of its own entry (applies as a self-removal at any time, `judge`, core/perm/src/walk.rs:1976-1983; `lowers(None, _)` is true), a put of Z at admin (does not apply), and a `/secrets` delta of puts keyed to Z and history keys up to admin. `valid_on` (core/engine/src/apply/validity.rs:732-740) sees an applied op on T and no overreach (`grantee_boxes_only` checks against every put, validity.rs:557-563); the delta is valid. Extra live entries under existing box and history keys then sit beside the genuine ones (spec/crdt.md §5.6); with a current reader, entries that open and lie (issues/history-box-poison.md); a removed member can add junk.

Note: spec/commits.md §2 allows several edges in one commit only for a redemption or a multi-removal; nothing on receipt enforces it.

Spec: spec/permissions.md §2 (exemption for invite grants only).

Fix direction: exempt only when an op on that thing applied as an invite-grant put (`Attr::By(Class::Invite(_))`, edge `Some`), and check the boxes against those applied grants' grantees and roles. Consider refusing as bad input membership commits that write more edges than spec/commits.md §2 allows.
