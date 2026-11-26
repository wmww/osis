# A removed node's links are untested
> Summary: spec/permissions.md §7 (removed node's links) is built (a removal from S does not end a link): `Account::remove_node` (libs/account) returns S's links still working and any node of the account ends them (`links_are_the_accounts_spec_permissions_7`), but no test removes a node while a link stands: the list returned non-empty, the removed node still joining through L, and nothing after `revoke_link`.
> Priority: normal
> Tags: tests, accounts
