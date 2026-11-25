# A paired node's grant to its own account on a nested thing is left out of the roster
> Summary: Bob's paired node (holding A by the pairing grant) grants A admin on T, minted with admin T0, itself minted with admin A: the commit is valid at both of A's nodes, yet T's roster leaves the grant out; the same grant by A's minting node (holding A by its record edge) stands.
> Priority: normal
> Tags: engine, perm, accounts

Repro: osis-sync `holding::repro_a_paired_nodes_grant_to_its_account_stands` (siblings: node 1 mints T0 with admin Bob's account and T with admin T0; node 2, paired, grants the account admin on T; T's roster lists T0 alone at nodes 1 and 2). Ignored on it: `holding::a_mint_admins_readers_read_a_thing_again_once_granted_again_spec_permissions_3` (removing T0's record edge after that grant is refused `LeavesNoAdmin`).

Probed: a grant by node 2 of read to another account on T stands; node 2's admin grant to the account on T0 itself (not nested) stands; node 1's admin grant to the account on T stands. So the walk drops an edge write naming as holder the account the signer reaches T through, when the signer's hop into the account is an edge write (the pairing grant) and T is a record edge further down. Not studied in osis-perm's walk; roles-model `tiny_keys` (pairing a grant to a node thing) has not drawn a grant naming the signer's own account on a nested thing.
