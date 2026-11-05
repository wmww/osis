# Removing immutable owners
> Summary: In discussion with Tess, nothing decided or built. What owners do today, how to replace them with no immutable owner, the limit on any conflict rule, and the options compared.

## What an owner does today
1. Fixes the tid (the record commits to it), so nobody can publish a competing creation. Needs only a genesis, not an owner.
2. Inheritance: a role on an actor reaches what it owns, so a million things need no edges.
3. Plain things derive secrets from the owner and store none.
4. Irremovable top authority: the only thing that settles a backdating fight (issues/ownerless-first-admin-backdate.md).
5. Roster snapshots: owner-chain only, so an ownerless thing's role history grows forever.

## Common base of every option: the first admin
Every record names a first admin, as ownerless records do; its edge is implicit, costs no bytes and is removable. The chain walk follows these edges while they stand. 1-3 keep working: same tid forever, plain things stay free and derive secrets until they get another holder, then rotate (exists today). Owner chain authority class goes away or becomes a role level. A move is grant + remove with no tid change; a large set moves by handing over a shared actor (existing usage rule). Key actors stay: a device is its key, not an owned thing. Verifiers must now see a record edge's removal, with the eventual reach of any edge.

## The limit on any conflict rule
An ex-holder signs two conflicting writes and controls everything in them (stamps, hashes, frontiers). A rule reading only signed data has three outcomes: the signer picks the winner (any tiebreak), nobody wins (burn), or someone else's signature decides (quorum, witness). Age cannot bound it without breaking "state is a function of held data".

## Options
- A. Admins only, earliest stamp wins (today's ownerless everywhere). No rule change; an ex-admin can steal back. Hidden owner stays.
- B. Admins only, a mutual removal neither side listed removes both. An ex-admin can only burn. A stolen device can wipe out all admins of a person.
- C. Owner as a mutable role above admin, zero or many holders, first admin holds it, with B's rule at the top. Stolen device loses to a recovery key holding the role; ex-owner can burn the top tier only and admins keep working. Two concurrent hand-offs make two co-owners rather than a conflict. Roster snapshots go to this role. Care: an admin of P must still act fully on things P holds (today's chain class), or a person's devices lose power over the person's things.
- D. Majority of the other admins on contested removals. Thief loses 2 to 1. Falls back to B below 3 admins; sock-puppet grants need a baseline. An add-on.
- E. Optional witness a thing names, ordering its role changes. The only real prevention; conflicts with "no trusted coordinator" unless opt-in; the witness needs its own hand-off.

- F (Tess's idea). Admins only; a fight goes to each user. Details below.

## F: disputes
- **Dispute**: an admin removal R of X, and a write W by X not listed in R's frontier that would void R. Every other conflict keeps today's rules, so honest histories prompt only when two admins really do remove each other (or knock out the other's grantor).
- **Pick**: a user's local choice, written as a demotion of the loser with a frontier, applied only in that user's view. The walk takes it as one more input (a seed for D); a pick rejects the author, so that key cannot raise another prompt. Published so the user's devices and others can follow it. State becomes a function of held data plus own picks.
- **Automatic pick**: own or own person's pick; else, if one side's write was stamped well before this node first received it and after the other side's, that side backdated and loses. Connected honest nodes all see this alike. Else, neither side gets new keys from this node and the user is prompted; a non-interactive node follows other admins' published picks or waits. Always warn.
- **Costs**: users picking differently split one tid until someone re-picks (a social fork); contacts judge a person's dispute out of band, like a safety-number warning; a host follows one step chain, so the losing side needs a replacement label (notes/sync.md); first-seen evidence is local, so it only sets a pick; tests need convergence "given equal picks". Changes spec/requirements.md Deterministic and API. Not model-checked.

- **Erase and come back** (Tess, as for purge races): a node removed under its default side erases as today, no holding period; if that turns around it re-syncs. Lost data when no copy is left is accepted. No exception to forward security or remote wipe. A device that wrote its own removal first holds it first, so it stays on its own side and keeps its data. Needs one rule: a removal whose frontier drops another's removal of G is delivered to G's inbox, like a grant (spec/permissions.md §2), because G stopped syncing the label and has no other way to hear. G then claims the label again. Not traced in code.

Leaning (before F): base + C, D or E later if wanted. B's rule in the walk is untested: `core/test/roles-model` found loops in similar rules (removal rings), so model-check before building. Also touches spec/requirements.md Permissions (three concepts, fixed owner, owner's snapshot). Would settle "owning vs collecting" in notes/realms.md: made in a realm = the realm is first admin.

## Optional recovery key (Tess's idea; documented, not built first)
Tess: having none must be a fully valid way to use the system, and a thief with an unlocked device taking control is accepted: the alternatives are no irrevocable actions for legit users, or a recovery system, which stays optional. So people get no recovery key by default and it is not in the first build. Lost-all-devices needs no new role: a recovery card can be a key actor holding a plain admin edge, listed by static entry as link keys are (spec/permissions.md §8); a thief can remove it. If built later, it is a separate section nothing else reads; every rule and test must work with none. "Owner" leaves the spec, code and API. Formats change freely until stability, so nothing needs reserving.

At most one key actor per thing, named in the creation record, none by default. It holds boxes like an admin (it must see the log to write frontiers, seal to new admins and register steps at hosts), so "only changes grants" is a client rule: it could always grant itself read. No admin can remove it; its role writes always apply and settle disputes, so a split tid converges again. It acts on the named thing only, not on things below by path (no class-by-path logic).
- **Hand-off**: it names a successor, then burns.
- **Burn**: a signed list of its writes that count; any other write of it is void. Several burns intersect, so a thief with the key can only cancel recovery, never gain from it.
- **Threshold**: split the seed outside the protocol, no format change.
- **Adding later is the weak point**: an ex-admin could claim to have added one, stamped in the past, or void the honest grant by removing its granter earlier. So added-later is only as strong as a normal admin write. Start with record-only.
- `Class::Chain` goes in the first build; a later recovery key adds back one small rule. Not modelled.
