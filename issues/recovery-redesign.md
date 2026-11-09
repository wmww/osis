# Recovery, from scratch
> Summary: Recovery (the recovery key, `RecoveryCard`, `restore`, CLI `restore`) is not in the API until a design is agreed (Tess). Not urgent. Needs Tess's input.
> Priority: low
> Tags: api, permissions, tess-call

Taken out because it was tied to saved peers (no card without them, the key discarded, issues/net-rework.md) and Tess wants it rethought whole. notes/disputes.md records her direction: no recovery key by default, and a stolen unlocked device accepted. notes/disputes-plan.md makes a recovery card an ordinary key holding an admin role.

Until then an account is reached again only through one of its other nodes.

Nothing of recovery is left in the engine: `create_person`, `Engine::recover`, the recovery key the account was minted with, `osis_label::RecoveryCard` and the recovery tests (core/node/tests/it/flows.rs) and the `disk_loss` sim scenario are removed. What it did, from a card (a key holding an admin edge on the account): a fresh node took up the card's key by `hold_key_actor`, granted itself admin on the account as that key, and removed each lost node by an explicit demotion with rotation. It was reachable only from tests and the sim. Accounts as built (spec/permissions.md §1) have no owner key apart from their epoch seeds on D, so an account with no node left is not recoverable. A redesign starts from the epoch seeds. The spec says nothing of recovery cards.

## Not in the API
`RecoveryCard`, `Osis::restore`, `internals::restore`, CLI `restore`, and a card from `init`; `Osis::create` returns just the `Osis`. No app UI had it.

## A restore race to design around
A head that moved while a fresh node read the home group by the card's key stranded that restore for good (5 of 32 sweep points with one saved peer, 6 of 60 with two): the label went `Stranded` with nobody to re-seal to (the node was on no roster yet). Admitting the card's key in `rest_tries` (`Some(t) == via`) did not help alone; a fresh attempt worked. A redesign that claims a label by a static entry meets the same race. Also: `SyncState::Stranded` is any one saved peer's `Phase::Failed`, so one peer that no key opens keeps a group from `Synced` while another serves it.

## Questions for the design
- Is recovery an explicit act after `create`, any time, with or without peers?
- Where the data comes from on restore: any node of the account, saved peers, or an address typed in.
- How a lost or stolen card is revoked.
- Interaction with disputes (notes/disputes-plan.md step 3).

## Tess's idea: an optional key
Having none must be a fully valid way to use osis, and a thief with an unlocked device taking control is accepted (the alternatives are no irrevocable actions for legit users, or a recovery system, which stays optional). So nobody gets one by default and it is not in the first build. Losing all nodes needs no new role: a recovery card can be a key actor holding a plain admin edge, listed by static entry as link keys are (spec/permissions.md §7); a thief can remove it. If built, it is a section nothing else reads; every rule and test works with none.
- At most one key actor per thing, none by default. It holds boxes like an admin (it must see the log to write frontiers, seal to new admins and register steps), so "only changes grants" is a client rule. No admin can remove it; its role writes always apply and settle disputes, so a split tid converges again. It acts on the named thing only, not on things below by path.
- **Hand-off**: names a successor, then burns. **Burn**: a signed list of its writes that count; any other write of it is void; several burns intersect, so a thief with the key can only cancel recovery. **Threshold**: split the seed outside the protocol.
- **Must be addable later** (Tess: nothing users may want to change is baked into a thing). An ex-admin could claim to have added one, stamped in the past, or void the honest grant by removing its granter earlier, so an added key is only as strong as a normal admin write. Accepted if built. Adds back one small rule; not modelled.
