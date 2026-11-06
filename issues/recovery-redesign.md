# Recovery, from scratch
> Summary: Recovery (the recovery key, `RecoveryCard`, `restore`, CLI `restore`) was removed from the API until a design is agreed (Tess). Not urgent. Needs Tess's input.
> Tags: api, permissions, tess-call

Removed because it was tied to saved peers (no card without them, the key discarded, issues/node-host-unify.md) and Tess wants it rethought whole. notes/owners.md records her direction: no recovery key by default, and a stolen unlocked device accepted. notes/owner-removal-plan.md makes a recovery card an ordinary key holding an admin role.

Until then an account is reached again only through one of its other nodes.

What stays inside: the engine still mints a key for the account's creation record while owners exist, and drops it. Spec text on recovery cards is marked as not built.

## Questions for the design
- Is recovery an explicit act after `create`, any time, with or without peers?
- Where the data comes from on restore: any node of the account, saved peers, or an address typed in.
- How a lost or stolen card is revoked.
- Interaction with disputes (owner removal step 3).
