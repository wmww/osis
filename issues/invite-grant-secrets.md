# Invite grant `/secrets` resets
> Summary: An invite grant's `/secrets` part is exempt from the admin rule only while it writes its grantees' boxes, but map resets carry no key, so resets of box entries this node has not seen and every history reset pass the check; an invite holder (any read-link holder signing as L) can still delete boxes or history boxes it names by dot.
> Tags: security, permissions, node

Scenario: a reader with invite (or a read link's L) writes an invite grant whose `/secrets` delta also resets other entries by dot. `apply/validity.rs::grantee_boxes_only` checks keyed puts (grantee, role at or below the granted one) and resets of box entries whose key `box_keys` knows; a reset of an unknown entry, or any history reset, passes. Effect: lockout of the named members (or of later grantees' history) until a re-seal; nothing becomes readable. Test of the checked part: `apply::validity::tests::invite_grant_secrets_limited_to_grantee_spec_perm_2`.

Recommendation: make the rule checkable from the delta alone: either a grant writes boxes and history boxes as puts only (no remove + put; `flows::put_secrets` needs another way to rewrite an unchanged value), or spec/permissions.md §2 says an invite grant's `/secrets` delta has no resets and the writer side follows.
