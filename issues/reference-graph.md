# The reference graph: one plan for sync, holding, lifetime, invitations and storage
> Summary: Tess's design, decided with her. Every reference is a strong, a weak or a ticket; a strong says "this belongs here" and grants nothing; a node holds exactly what its node root reaches by strongs, entering a thing with its own keys only by a ticket it can open; a thing goes when its last reference goes. What a sync ID carries stays today's rule (what its keys can open). Invitations become tickets fired on an account's inbox thing, on a signal anyone holding the account's public record may fire. Removes retainers, release requests, synced groups, default filing, the group concept, inbox blobs, grant copies, the acted-on set, the account's sync records, tied grants and the `delete` call. Built after the account forks work, by demolition and rebuild on main.
> Priority: normal
> Tags: engine, sync, data-model, permissions

## Status
- On main: this plan, the spec (it describes the rebuilt design, not the code), the requirements wording (Tess approved), the model (notes/closure-model.md, held-model `closure`).
- Execution steps 3 (demolition) and 4 (foundation, Lanes below) are done; the lanes are next; the spec's account parts are in the account forks terms (notes/engine-validity-epochs.md: seeds boxed to device keys, the chain is D's roster, merges only join).
- Lane (b) built (notes/node-closure.md); the making rule (spec/sync-set.md §2 Making a thing) is not enforced yet: it refuses about 700 engine tests whose helpers make things with no strong, so it lands with step 6. Tickets entering a thing wait on lane (c)'s `ticket_for`.

## Principles (Tess)
- **A strong grants nothing.** It says the target belongs to this closure; anyone knowing a tid may write one. Permission is a separate act by someone who may grant, and removing a reference revokes nothing.
- **A thing goes when its last reference goes**: every node holding it releases it, waiting for no absent peer; once no node holds it, a strong to it reads as not held (spec/sync-set.md §3). That is the intended result, never a risk to design around: nothing is kept because a release might be a mistake.
- **Core holds only what cannot be built correctly on top of it.** Home, which invitations to accept, contact lists and "what is on my other nodes" are the app's.
- **Lean on osis for storing data.** Node and account state are ordinary things and aspects. No aspect is exempt from sync; what is local is local by where it sits.
- **One mechanism, reused.** A ticket is the one way to say "here is how to sync this", wherever it is stored.
- **Nothing grows only.** No set of everything ever seen, accepted or granted.

## Terms
- **tid**: a thing's ID. Never a value.
- **ref** (reference): a strong, a weak or a ticket inside a value.
- **strong**: a ref that makes its target part of the closure. **weak**: a ref that only points.
- **ticket**: a weak that also carries what is needed to sync its target (Tickets).
- **Own keys**: a thing with role secrets of its own, and so a sync ID. **Plain**: a thing without; its keys derive from where it was made.
- **Closure** of a thing: it and everything reached from it by strongs, transitively. A closure is a set; the thing it is taken from is its **root**.
- **Sync unit** of a thing T with own keys: T and what T can reach by strongs and itself read; a subset of T's closure, what T's sync ID carries (Sync units).
- **Node root**: the one local thing per node whose closure the node holds. **Node closure**: what it holds of that closure. **Node thing**: the node's face to its account (keys, addresses); a different thing.
- **Account**: the identity (a key actor: signs, is granted roles, has no member list and no sync ID). **Account root**: the private thing beside it, read by the account's nodes only. **Profile**: name and dial addresses, read by contacts. **Inbox**: where others reach the account.
- **Home**: the app's, not core's: an ordinary thing a user's nodes may all hold.
- **Release**: a thing leaving a closure, and what holds it there dropping it. The one word; "unsync" is not a second term.
- **Tag**: the user-facing grouping, kept. `holds.0`: the core aspect that is a plain set of strongs and weaks. `tickets.0`: the core aspect that is a plain set of tickets.
- Gone: group, subgroup, item, synced group, filing, shared here, retainer, release request, invitation as a core list, grant copy, acted, sync record, tied grant, delete (as an API call), devices (issues/deprecated-terms.md).

## Design
### References
- Three values, each its own CBOR tag; tag 1616 is retired and no value is a bare tid. Schema types `strong`, `weak`, `ticket`, and `ref` (a strong or a weak, the writer picks per value); the type `tid` goes. No default strength anywhere: encoding, API and schema each make the writer choose.
- Rust: `Strong`, `Weak`, `Ticket`, `Ref`. `Tid` converts into `Strong` and `Weak` with `.into()` and each converts back; a read returning a ref may return its `Tid`. A `ref` field makes `.into()` ambiguous, so the writer chooses.
- Types bind the local writer only (spec/versioning.md §5): a peer may write any ref where it may write, and nodes act on what is in the data.
- A strong and a weak to one tid are different values; a target is held when any strong to it counts. Schemas type map keys; no rule bars strong keys.
- **What counts**: every strong in the current state of a thing, in any aspect, at any depth and value size (issues/refs-in-chunked-elements.md), ephemeral aspects included while the value is held. History never counts. A signal has no current value, so a strong in a signal entry keeps nothing.
- **Index**: one index of every ref in data the node holds and may read, held signal entries included, with its kind. It serves the closure walk, the ticket lookup and backlinks. Backlinks list everything: no excluded aspect. Creation records and role records hold weaks; a role record's current value is its roster.
- `osis://` links in text become weaks: issues/text-links-as-references.md (independent).
- `holds.0`: the plain container for the node root, the account root and tags; `tickets.0` the plain container of tickets a thing holds (the account root's for the profile, the inbox, link actors and redeemed targets). `tid.0` and `groups.0` go, as aspects and as calls (the groups-of call with them): a handle carries its tid, and what holds a thing is its backlinks, each with its kind and AK (a tag's strongs are in its `holds.0`).

### Sync units: what a sync ID carries
- **The rule, in one sentence: a thing's sync unit is what it can reach by strongs and itself has read access to; it stops at the first thing it has no read access to.** A closure is what is referenced; a sync unit is the part of it that syncs as one, under one sync ID, and equals the closure only where the root reads all of it. Nothing is called a sync closure. Read access is the root thing's own (it is above the target in its chain of admins, or was granted read on it, directly or through a thing it holds a role on), never that of a person using it. With it: one also holds a thing one reaches by a strong where one was granted a role on that thing oneself (a ticket); and a thing goes when nothing carries it and nobody holds it so. Diagnostics and errors use these words ("B references T but has no read access to it, so T is not in B's sync unit").
- Stated behaviour that follows: Alice's closure A is admin of T and references it; Bob, a reader of A, adds a strong to T in his closure B; Alice removes hers. B never carried T (Bob had read on T, B did not), so T is gone for both. It survives where Alice shared T with Bob or with B. Likewise a thing reached only through a thing the root loses its role on is carried no more.
- Why carrying is not tied to the unit of permission: a closure granted read on a large thing carries just what it references of it, so one row of a table syncs without the table and without a set of keys per cell (spec/requirements.md, no unit synced whole).
- The API has no notion of a thing with or without own keys: a first grant makes them. Apps choose a thing's first admin: content is created under the thing it lives in (whose readers read it). A thing made under the account is in no sync unit and stays on the node that made it; a new root made under the account gets its own keys at creation and is held by ticket; account-wide plain things are made under the account root. Sharing a thing shares its sync unit, never what it only references: to share a tag of notes made under home, the app grants the tag a role on each note (when the tag is shared, and for each note added later), and the warning below names each one it missed. A call that does that sweep is the API's to consider (notes/api-design.md).
- Today's rule, kept (spec/sync-judgement.md §1 Entitlement): T's sync ID carries the things of T's closure that T's own keys can open, plain or with own keys: a thing whose secrets derive from T's, or on whose reader actor T holds read or above. The walk continues through such a thing and stops at any other. That is T's **sync unit**.
- So a thing may be carried under several sync IDs (stored once per node), and a plain thing needs no keys of its own to be in two closures: the second must have been granted read on what its keys come from. A thing with own keys is always carried under its own sync ID too.
- Every reader of T reads all the walk reads, so every reader computes the same sync unit. A strong to a thing T's keys cannot open carries nothing under T's sync ID.
- Sharing Y with everyone who has X is a grant giving X read on Y, and a strong. Nodes that only store X then store Y with it. Nothing ties the grant to the strong.
- A plain thing is carried under T's sync ID only while T's sync unit holds it: none is carried for being made under an actor. When a sync unit no longer holds it, each holder drops its copy by its own view, and holders of the delete key delete the stored entries; a node whose view still holds it logs it again.
- Limit, as today: an edit of a thing carried under two sync IDs reaches a node syncing only one of them through a node that syncs both.
- A role change travels, as today, as a certificate under every sync ID whose sync unit depends on it, ahead of the deletes it causes (spec/permissions.md §4 Role changes travel, spec/sync-judgement.md §2, §3): a revoked grant reaches every node holding what the grant carried. Without it two nodes undo each other for good (notes/closure-model.md).
- No rule is special to the account: a thing made under the account itself is in no sync unit (nothing but the account has read access to it), so it stays on the node that made it. Apps make account-wide things under the account root.
- Making a thing: the commits a node makes in one storage transaction must leave every thing they make in the node closure at its end, or they are refused. That covers the account's creation (P, D, the profile, the inbox and the node thing, with the node root's strong to D, as separate commits by P and by the node) like any write. Key actors (accounts, nodes, link keys) are in no closure and exempt. Nothing is filed by default.

### Holding and release
- The node root is local: it has no sync ID and nothing references it. It holds the node's strongs (`holds.0`), its settings, its strong to the account root (never removed), and what is local to a node today (`caps^.0`, `clients^.0`).
- The node closure is walked sync unit by sync unit: within a sync unit by its strongs; into a thing with own keys that the sync unit's keys cannot open only where the node holds a ticket for it that it can open (found by tid in the index) or already holds its keys. With none the walk stops there: reading it is an error, nothing else is affected. With a ticket for the sync role only, the node stores that sync unit unread and the walk stops.
- The walk does not enter a key actor (an account, a node, a link key): it has no sync unit. What a node holds of a sibling's node thing is its public record under the account root's sync ID.
- A strong to a thing the node never got holds nothing: if its last holder releases it first, it is gone, and the strong reads as not held. Destroyed, released and never held all read absent: no marker tells them apart.
- A ticket enters its target at the lower of its role and the holder's: a read ticket whose holder was lowered to sync keeps the thing unread; one whose holder has no role enters nothing.
- Core gives sibling nodes no view of what a node holds. An app may publish a list of weaks.
- A diagnostic (`NotCarried`) lists each strong in the node closure whose target is not carried where the strong is and not held otherwise, strongs to key actors excluded. A write adding such a strong is not refused: it reports the same diagnostic at once, as a warning.
- One wait stays: a node that removed itself from a thing keeps its secrets until its removal is held elsewhere (spec/permissions.md §3): that delivers a message, it preserves no data.
- **Release**: a node drops what left its closure once the sync pass in flight with its connected peers has ended: it has fetched what joined, served what those peers wanted, and found the thing still outside its closure. With none connected, at once. It never waits for an absent peer. Its unsynced writes to a released thing go with it. A released thing is not destroyed: it may be fetched again where something references it. Nothing of it stays but what a held thing needs to verify its own authority, which travels as certificates under the sync IDs still synced.
- Purge and expiry are unchanged. Evidence of a destroyed thing is kept only while a held thing depends on it for authority (spec/commits.md §5 Destruction): the clauses for listed retainers and for references go.
- No `delete` call: removing a strong is an ordinary write, erasing is purge, clearing aspects is the app's own writes, and undoing a creation is a plain revert of its commit (which removes the strong it wrote).
- Removing a strong costs at most the subtree it held, never the target's fan-in: each held thing records one edge towards the root; removing another edge is O(1); removing that edge marks the target's subtree, re-attaches each member a held referrer outside the subtree still reaches (and what those reach), and drops the rest. Checked against a from-scratch walk in the model, cycles included.
- Limit, as today: in an admin dispute the sides differ on what is valid, and so on what belongs.

### Tickets
- A ticket holds: the target's tid, its sync ID, one secret of it (read, or sync for a holder that only stores) with its epoch, sealed to a named actor, and the issuer's profile tid. No addresses. About 1.3 KB (a seal to an actor's KEM key).
- It is a weak: it keeps nothing. It is ordinary data and works wherever the node holds it: an inbox entry, a message attachment, a document's source, the account root's ref to home. Core never copies one.
- A ticket is made by a node that may grant the role, by a node changing the thing's keys for each holder the change boxes, or by a node for its own account of a thing it holds a secret of (it grants nothing: the account already holds the role). Anyone may copy one.
- **The account's tickets**: D's `tickets.0` holds a ticket sealed to the account for each thing with own keys that the walk enters at a strong outside the node root's local part, at a current epoch: a node entering one or holding a newer epoch with none in D writes it (replacing older ones), and a node releasing the thing removes it. One rule gives the profile's and the inbox's tickets, a link's K, a redeem's and a card import's, and every accept's, and keeps D's tickets to what is held. So the account's other nodes, one paired later or one offline past the inbox's history included, enter what the others accepted.
- **Accepting** is writing a strong to the target; the node finds the ticket and so writes D's. **Declining** is doing nothing. There is no invitation list in core and no record of what was acted on.
- A ticket's sync ID is its issuer's word until a step of that sync ID bears a key of the ticket's secret.
- **Left out**: a holder whose grant and a rotation were made concurrently (neither maker held the other) holds no box at that epoch until a node that may rotate re-seals it or a rotation supersedes it (spec/permissions.md §3 Left out): the requirements' limit, computable from the history.
- **An old ticket**: as today, an old secret alone opens nothing. A reader that is behind catches up where a reading peer opens on its role (spec/sync-opens.md §4); a node changing a thing's keys fires a fresh ticket to each holder that only stores it and to a holder granted again after a gap. Limit: a new node starts from an old ticket only where it reaches a peer that reads the thing. A possible follow-up: issues/one-open-proof.md.
- The profile tid in a ticket is a dial hint, never proof of the issuer. Addresses live in one place per account, its profile's dial list; a node tries every connected peer for a sync ID it wants; a contact card is the one thing that carries addresses.

### The inbox and `@` signals
- No new role: the roles stay sync < read < write < admin.
- `@` in an aspect key (as `ticket@~0`; valid only with `~`, never with `^`) marks a signal that anyone holding the thing's public key record may fire: the fire is a commit by the sender's own account, sealed to the thing's public key, delivered as a deposit signed with the deposit key, within the deposit budget (spec/sync-inbox.md Deposits). A writer's node promotes one whose signature and author's chain verify. The deposit seed stays in the public key record, as today.
- `@` is not valid with `+`: a deposit is never relay-only. A sender cannot read the thing's history setting, so the receivers' setting alone decides how long a fire is kept. Delivery ends when a peer holding the inbox takes the deposit.
- Who fired it is the commit's author, verified by its chain. Blocking a sender is the app's; storage budgets and rate limits are a separate project.
- **Inbox**: a thing per account, read by its nodes only, named in the account's public record as today, with three `@~` signals: arriving tickets; removal notices (the signed removal's role parts; a node acts on one only after checking it against the member list it holds for that thing, then releases the thing or keeps a retained copy as the removal says); and stranded notices (a node that cannot read a thing's current epoch, with no writer connected, fires one on that thing, naming the holder to re-seal, for writers to see later). How long entries stay is the inbox's own history setting.
- A removal notice is fired for any change taking a reader below read. A re-seal fires a fresh ticket as a key change does. The node making a grant fires its ticket. An actor that is no account (a team, any thing with a sync ID) is its own inbox: the same three signals fire on it.
- Nothing an arriving ticket names is fetched, dialed or applied until a strong in the node closure reaches its target. The walk enters at any strong in the node closure where the node holds a ticket it can open, not only one the account wrote. Limit: a writer of a thing the node holds, who can also get a ticket to the node's account, makes the node fetch that ticket's target.
- Whoever changes a thing's keys or removes a member reaches that member's inbox by the member's public record, which every fellow member holds.
- **Contact card**: a link giving read on the profile; the profile's sync ID carries the account's public record. An invitation from a stranger carries a ticket for the thing and one for the sender's profile.
- The account's things: the account root strongly references the profile, the inbox and the node things, holds in its `tickets.0` a ticket sealed to the account for the profile and for the inbox (it has no role on them, as on home; both have own keys from the account's creation), and by the same rule (The account's tickets) one for each other thing the account's nodes enter, home among them.

### What goes
Gone (step 3): retainers, release requests, `released.0`, lifetimes, synced groups and `synced^.0`, shared here, default filing, the group concept (`group.0`, `groups.0`, the group index and key homes, `Write::group`, `Member`, groups_of, `members`, `add_with_grant`), tied grants, inbox blobs (every payload kind, taking, hints, deliveries, grant copies), invitations and `acted^.0`, the account's sync records (`kept^.0`, offers), `delete`, `tid.0`, `home()` as a public call, the NetTrust model, and every test of these, the sync differential and the sim set included (rewritten at the end).
Left to the lanes: the tid value (lane a), the reference index's exclusions (lane a), `caps^.0` and `clients^.0` on the node root (lane b), app, kit and chat (the agent after the lanes).

### Storage
Every stored row hangs off something the node closure holds, a store entry of a sync ID it syncs, a peer record, or the node root; a row goes with its last owner. Releasing everything leaves the node root, the account root, the profile, the inbox and the node thing, plus only these, each bounded:
- fires on the inbox, for its history setting (`INBOX_LIFETIME` by default);
- siblings' node things under D, while they are on D's roster;
- a link's sync ID while it is redeemed, until the join is held or the redeemer stops (spec/sync-inbox.md §6);
- a destroyed thing's sync IDs until emptied, at the latest past its destroying requests' expiry (spec/sync-judgement.md §5);
- role changes carried under a former grantee's sync ID, for `ROLE_KEEP` after replaced (a removal: after its `ts`, spec/sync-judgement.md §2);
- tombstones for `TOMBSTONE_LIFETIME`, peer records within `RECORD_BUDGET`.

The audit of today's exceptions: issues/storage-follows-groups.md.

## Execution
Main may be broken for as long as this takes: nobody runs it. No small steps that keep things working, no long-lived branch.
1. **Spec first.** This plan and the rewritten spec land before code, with the model.
2. **Baselines**, by the executing coordinator on its own box: the default tests' count and CPU seconds (`tools/pertest.py run`), and `tools/loc.py`.
3. **Demolition**, one sync unit of work: delete everything in the inventory and every test of it, including tests that could be ported. The tree only has to compile.
4. **Foundation**: one commit declaring the new types and empty modules, so the lanes do not collide.
5. **Rebuild in three lanes at once**, each one worker and one reviewer, committing to main: (a) ref and ticket values in place of the tid value, schema, API and the index; (b) the node root, the closure walk, sync units by strongs, release; (c) `@` signals, the inbox thing, tickets in sync, removal notices. Lane workers write only the tests they need to develop their lane; the planned set (notes/refgraph-tests.md) waits for step 6. Then one agent brings app, kit and chat back: they create each thing under the thing it lives in (its first admin, whose keys it takes), not under the account, since a thing made under the account is in no sync unit and stays on the node that made it (a new root made under the account gets its own keys at creation and is held by ticket; account-wide plain things go under the account root); default filing goes.
6. **New tests last**, the planned set of notes/refgraph-tests.md, from the properties here and the model: small and cheap, plus the count test of Storage, a new sync differential and sim set.
7. **One gate**, at the end.

Rules:
- **No bridges**: no interim path, compatibility code or old thing kept until the new one works.
- **Cut everything that makes sense to cut**, and report source lines before and after (baseline 141,662 impl and 123,333 test lines at 5b4faadfa; the inventory estimates 4,800 impl lines removed). A lower total is the aim, not a condition.
- **Fewer and faster tests**: the default tests' count and CPU seconds are lower at the end than the baseline of step 2 (5b4faadfa: 3,493 default tests, 7,030 G instructions, 2,372 CPU-s; `tools/pertest.py` output kept in `~/osis-refgraph-baseline/pertest` for `compare`; the inventory estimates 8,000 to 9,000 test lines removed). A condition.
- **"Group" is never renamed by search and replace.** Each use is read and becomes a closure, a sync unit, a tag, `holds.0`, or is deleted with what it described; about a quarter of its uses mean something else (delete-key groups, block-list groups) and stay. Reviewers sample each outcome.
- No benchmark or timing run is part of the preparation: each is a step for the executing coordinator.
- About ten agents in all.

## Lanes
Each lane owns its files; a stub's body is `todo!("refgraph: (x) ...")` or a no-op marked `// refgraph: (x)`, its doc comment naming the spec section (`rg 'refgraph: \(a\)'` lists a lane's).
- **(a) references**: `core/base/src/refs.rs` (`Strong`, `Weak`, `Ref`, `Ticket`, `Ticket::{to_value, from_value}`), `core/base/src/format.rs` `TAG_STRONG`/`TAG_WEAK`/`TAG_TICKET` (1616 retired as `TAG_RETIRED`), `Value`'s variants and `cbor.rs`, the schema types `strong`/`weak`/`ticket`/`ref` (`core/schema/src/{types,parse,schema,typed,codegen}.rs`) and `holds.0`/`tickets.0` in `schema/core.osis` and `core_types.rs`, the osis re-exports (`core/osis/src/lib.rs`) and the write and read API for references, the reference index (`core/engine/src/engine/refs.rs`: every aspect indexed, the kind per row), vectors.
- **(b) holding**: `core/engine/src/flows/roots.rs` (`node_root`, `account_root`, `hold`, `unhold`), `core/engine/src/sync/units.rs` (`sync_unit`, `units_holding`, `unit_settled`), `core/engine/src/sync/set.rs` (`sync_things`, `in_sync_things`, `things_entered`, `caught_up`, kept unread in `thing_sync_now`, `set_sourced`'s cut), `core/engine/src/retention/release.rs` (`left_closure`, `released`) with sync's `leave`, `Engine::readable_by`'s sourced check (`engine/acting.rs`), the `NotCarried` diagnostic (`DiagnosticKind::NotCarried`, osis `Diagnostic::NotCarried`) and the write path's warning (`core/osis/src/write.rs`), the account creation's roots (`flows/account.rs` `create_account_in`), the seed thing and K of a link and a client's actor held from the account root (`flows/links.rs`, `core/osis/src/clients.rs`), the differential's holding (`core/sync/tests/it/harness/history.rs`).
- **(c) inbox**: `core/base/src/ids.rs` `Ak::open`, `core/blob/src/fire.rs` (`seal_fire`, `open_fire`), `core/engine/src/flows/inbox.rs` (`fire_ticket`, `fire_removal`, `inbox_thing`, `ticket_for`, `take_removal_notice`, `fire_stranded`), `core/engine/src/sync/tickets.rs` (`ticket_sync_secrets`), a sync secret of a thing not read (`apply/keys.rs` `learn_secret`), the lowered-to-sync keep (`rotation/lost.rs`), a redeem's tickets (`flows/links.rs` `redeem_in`), dialing a ticket's issuer (`sync/dial.rs`), the stranded notice with no writer connected (`core/sync/src/inbox/stranded.rs`), promotion of sealed fires (`core/sync/src/inbox/held.rs`).

## Settled while building
- Edge removal runs both searches in step (the target's other referrers up their tree paths, and its subtree), stopping at the first answer: at most twice the smaller (spec/sync-set.md §2 Cost; `core/engine/src/sync/units.rs`).
- `caps^.0` and `clients^.0` sit on the local node root (spec/sync-set.md §1): simpler, and reversible; a sibling changing an offline node's caps waits on issues/settings.md.

## To settle while building
- D's deposit seed: the inbox is its own thing, so a fresh deposit seed on a device removal rests on every sync-role rotation writing a new one (the inbox thing and D rotate inside each P rotation); check it holds in the rebuild.
- What `tools/spec_map.py` needs once the removed sections go (`tools/policy_test.py` plants appended text in a missing file afresh).
- No bound on how many sync IDs one commit is carried under (nothing limits the sync units a thing is in): measure with issues/many-sync-ids-cost.md.

Not blocking: issues/many-sync-ids-cost.md (the cost of many things with their own sync ID, which a shared tag of notes makes).

Follow-ups, outside this plan: issues/links-as-tickets.md, issues/one-open-proof.md, issues/text-links-as-references.md, issues/refs-in-chunked-elements.md (needed by What counts).
