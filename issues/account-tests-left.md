# A removed account stays known by its own things
> Summary: `Judge::known` counts every role an actor holds through rosters held here, and an account always holds its own devices actor and profile (its node holds the devices actor), so an account removed from every group stays known: it keeps its record and resumes. Needs a rule for what "known" means with accounts.
> Priority: normal
> Tags: tests, sync, tess-call

`net_records::a_removed_node_no_longer_resumes_spec_sync_10` is ignored for this: after the removal, `roles_of` at the peer still names the account's devices actor and profile, so spec/sync.md §10 "a proven actor ... known here now" holds and the Resume is answered.

Excluding things the account made does not work: a group it made and shared counts. The rule would have to be "holds a role on something another account also holds" (O(roster) per check) or the like, in spec/sync.md Connection proofs and `Judge::known`.
