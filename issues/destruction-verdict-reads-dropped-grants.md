# A destruction keeps the thing's edges, and any admin may destroy
> Summary: Coordinator decision, for Tess to revisit if she likes: a destruction by purge keeps the thing's `roles.0` parts (metadata, no content) beside its record and the `purge.0` residue for good (nothing drops a request), and any admin at the request may destroy, as with any purge right. Done; open only as a decision she may change. It removed "only its creator's side may destroy it" from spec/requirements.md, which needs her sign-off.
> Priority: low
> Tags: engine, tess-call

The right to destroy is the ordinary purge right, so a removal of the first admin arriving after a destruction can make it fall. That needs the grant authorising the removal, which a destruction that dropped its thing's edges would not have: a node that took the destruction first and one that held the removal first would disagree for good, and their syncs would upload and delete the same blobs at hosts without end.

Rejected: reading the right from standing on the first admin alone, because a removed admin could then destroy a thing for everyone.

The cost is one thing's edges per purged thing, kept for good (issues/destroyed-thing-leftovers.md, notes/growth.md row 5). Reversing the decision means dropping `judges_destruction`'s `roles.0` and choosing what the right reads instead.
