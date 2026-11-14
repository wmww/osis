# A non-writer's grants to an actor are kept by the actor's inbox
> Summary: Grant copies (spec/sync-inbox.md §5) keep any author's edge write naming an actor. A reader of group G can mint things and grant G on each, and each joins G's required set: unbounded. Requiring the author's write on the actor (branch grantcopy-write) closes that but drops a stranger's grant to an account, which the account's later nodes need to list the invitation.
> Priority: normal
> Tags: security, sync, tess-call

**Tess question:** a grant from someone without write on the actor (a reader's grant to its group; any other person's grant to an account) must reach the actor's later nodes after its inbox blob expired (an invitation), yet keeping it for good lets that person grow what the actor's holders keep without bound. Which wins: keep such grants only once a writer of the actor accepts them (an untaken invitation is lost to nodes away past `INBOX_LIFETIME`), or let requirements' small budget count them (keep within a per-actor budget, oldest pushed out)?

Rule tried (branch `grantcopy-write`, `Engine::posts_to` in `grant_copy`): a grant copy only for an edge write whose author held write on the actor at its `ts`, from requirements' "posting into a shared space needs write on its actor". It passes `readers_reach::a_readers_grants_to_the_group_are_no_grant_copies_spec_sync_inbox_5` (reader mints 40 grants to g: 0 held under g; a writer's grant: held), and breaks the stranger-to-account flow:
- osis-sync `flows::an_accounts_node_away_past_inbox_lifetime_gets_the_grant_spec_sync_inbox_5` (account 0 grants account 1; node 2 of account 1, away past the blob's lifetime, never lists the invitation);
- osis-engine `facade::a_readers_grant_copy_carries_the_grant_spec_sync_inbox_5`, `a_sync_holders_grant_copy_is_its_box_alone_spec_sync_inbox_5`, `a_removal_replaces_the_grant_copy_spec_sync_inbox_5` (all grant to another person's account).

Unaffected: links (the sharer's actor is K's admin), grants by a group's writers or admins, realms' members' grants (a non-member's grant to a realm is dropped like a stranger's to an account).

Promotion is closed already: it needs the author's write on S's actor and a body S's closure carries (`readers_reach::a_readers_grant_to_the_group_is_not_promoted_spec_sync_inbox_4`). Sharing a thing with the group does not put it in the closure, so only the grant copy is at stake.
