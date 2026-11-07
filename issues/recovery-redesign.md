# Recovery, from scratch
> Summary: Recovery (the recovery key, `RecoveryCard`, `restore`, CLI `restore`) is not in the API until a design is agreed (Tess). Not urgent. Needs Tess's input.
> Priority: low
> Tags: api, permissions, tess-call

Taken out because it was tied to saved peers (no card without them, the key discarded, issues/networking-plan.md) and Tess wants it rethought whole. notes/disputes.md records her direction: no recovery key by default, and a stolen unlocked device accepted. notes/disputes-plan.md makes a recovery card an ordinary key holding an admin role.

Until then an account is reached again only through one of its other nodes.

What stays inside: the engine still mints a recovery key for the account (an admin by a plain edge) and drops it (`create_person`); the engine's `recover` and its node tests (core/node/tests/it/flows.rs: `stolen_device_recovery_spec_perm_7`, `recovery_erases_whatever_the_default_spec_perm_2`, ...) and `osis_label::RecoveryCard` stay until this redesign. Spec text on recovery cards (spec/permissions.md §7, spec/wire.md §10) is marked as not built.

## Not in the API
`RecoveryCard`, `Osis::restore`, `internals::restore`, CLI `restore`, and a card from `init`; `Osis::create` returns just the `Osis`. No app UI had it.

## A restore race to design around
A head that moved while a fresh node read the home group by the card's key stranded that restore for good (5 of 32 sweep points with one saved peer, 6 of 60 with two): the label went `Stranded` with nobody to re-seal to (the node was on no roster yet). Admitting the card's key in `rest_tries` (`Some(t) == via`) did not help alone; a fresh attempt worked. A redesign that claims a label by a static entry meets the same race. Also: `SyncState::Stranded` is any one saved peer's `Phase::Failed`, so one peer that no key opens keeps a group from `Synced` while another serves it.

## Questions for the design
- Is recovery an explicit act after `create`, any time, with or without peers?
- Where the data comes from on restore: any node of the account, saved peers, or an address typed in.
- How a lost or stolen card is revoked.
- Interaction with disputes (notes/disputes-plan.md step 3).
