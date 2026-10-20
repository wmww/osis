# Reading-only candidates from unknown authors share one budget
> Summary: Before a new member holds a shared thing's public keys, an insider sending 64 bogus pending commits under throwaway identities can delay the member's reading of that thing until its grant applies (no data is exposed, nothing is lost).
> Tags: security, keys, node

Repro: code reading (`osis_keys::RoleEpochs::set_reading_secret`, `apply/keys.rs::read_pending_boxes`).

Pending commits' boxes give reading-only candidates (spec/crypto.md §4). A candidate for an epoch whose keyset the node holds (`/keys`) must derive it (`prune_reading`), and authors whose `/created` the node holds get their own budget. Authors it does not know share one budget (`UNKNOWN_AUTHOR`, 64 per role). A grantee that holds neither the target's `/keys` nor the granter's chain yet (its grant is pending for exactly that reason) gets its genuine candidate refused once 64 unknown-author candidates fill that budget for the role. Effect: the grantee reads the target only once the grant applies (the pre-grant read of spec/crypto.md §4 is lost); the candidates go when their commits are dropped or apply.

Options: carry the target's `/keys` commit with every grant's inbox payload (the grantee can then check candidates before the grant applies), or rank candidates by the grant that names the node as grantee (a commit whose `/members` part grants this node outranks one that only boxes it).
