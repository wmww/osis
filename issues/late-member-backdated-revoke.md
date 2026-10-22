# A member offline through a backdated revoke judges the revoked writer's later write valid
> Summary: After a backdated revoke of writer B (frontier before B's write v2), an online member un-merges v2 and reads v1, but a member that was offline throughout and receives v2 and the revoke together reads v2: validity depends on arrival order (spec/permissions.md §5.2 says it must not).
> Tags: node, apply, tests

Repro: timed_dead.rs `late_member_judges_backdated_revoke_alike_spec_permissions_5` (ignored). Found while checking a late joiner for the revived keep-at-most body (the late member then also drops v1's body as dead under keep at most, so the "window, not a loss" verdict of notes/node.md holds only for members whose validity is right). Not yet diagnosed; a normal (non-backdated) revoke covers v2 in its frontier, so only a backdated one shows it. Likely in apply's validity path for a write applied after the demotion is already held (membership is ingested first, so a late member applies the revoke before v2).

When fixed: un-ignore the test and add the late member back to `revived_body_uploaded_again_after_timed_delete_spec_commits_5`.
