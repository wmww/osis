# Every independent thing takes every open signal and any grant
> Summary: Decided by Tess, to build: a thing takes an open signal only where its admin-only setting names it, and is granted roles by someone who does not administer it only where its admins opened it to that (accounts and the like; little else). Today every independent thing takes every `@~` name from anyone holding its public key record and publishes four KEM keys so anyone may grant to it: one of the reasons independent things are heavy.
> Priority: normal
> Tags: security, perm, sync, spec

Today (spec/data-model.md §2, spec/sync-inbox.md §2, spec/permissions.md §5.2 Open fires): a fire of an `@~` aspect of N is valid whatever its author's role on N. The only per-thing control is keeping: fires stay only where N's `retention^.0` names the signal, else they are out of history at once. To check: whether an unkept fire still reaches listeners and still spends the deposit budget at nodes keeping N unread.

## Decided (Tess)
- **Open signals: off unless named.** A fire of an open signal the thing's admin-only setting does not name is invalid, not merely unkept. The retention entry that keeps a signal's fires is nearly this switch already: make it the one rule, per signal.
- **Ordinary signals: no switch.** A writer may write any aspect of a thing, so a switch on signals alone would follow from no rule of the data model.
- **Being granted roles by a non-admin is an unusual property a thing's admins turn on.** A role grant involves the granted side: an account (or its profile or home, whichever takes it) has it, an org or realm has it, and not much else would. Readers of a shared document cannot say "whoever is on this document may read my thing" unless the document's admins allow it; they grant the accounts, or ask.
- **It is one switch with taking tickets.** A granter that does not administer the holder reaches it only by its public keys: the box is sealed to its KEM key and the ticket is a fire of its open `ticket@~` signal. Off: only its own admins make it a holder, publishing its keys in that commit, and another's grant to it is refused at the granter. On: as today. No grant waits for the holder's side to publish keys.
- **Keys follow the switch**: a thing neither a holder nor opened publishes no KEM keys (notes/thing-cost.md, Fewer KEM keys held), and a node keeping it unread has nothing a stranger can deposit against.

## Designed
The checks and the rule written precisely enough for the spec (the setting, open fires, public material following the switch, what a node keeping the thing unread enforces, what the thing takes, the granter's node, what a member may do without the switch): notes/write-path-design.md §4. Found: the box and the ticket are not the only routes (a deposit under the holder's sync ID with its public deposit seed is another), so the deposit seed and sync ID are published to strangers only while the thing is open.

## To do
- Whether granting to a thing not opened needs write on it or any role (the requirements say "holding no role"): issues/actors-one-mechanism.md, Questions for Tess.
- Bring spec/requirements.md Permissions and the subsystem specs to the rule. Name the refusal in the API by the setting, never by keys.
- How an app opens a thing, and what the default is for the kinds it makes.
