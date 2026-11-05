# Permissions
> Summary: The rules of actors, role grants and ownership, role secrets and rotation, certificates, validity (role timeline and content), roster snapshots, purge rights and links.

## 1. Concepts
- **Terms**:
  - Rights are **roles** (read < write < admin) given by **role grants** (**grants**; "edge" in rule text means a grant). An actor with a role on a thing is a **holder** of that role on it.
  - A **role commit** (spec/commits.md §2) carries writes of **role-class aspects** (spec/data-model.md §9).
  - The **role timeline** (§5.1) orders edge writes.
  - A **co-reader open** (proof 3, spec/sync.md §5) is a label open by a node that reads the label.
  - **Member**, **membership** and **member of a group** mean only placement in a group (`group.0`, spec/data-model.md §8), which grants no rights.
  - A value in a CRDT set is an **element**.
- **Actor**: a thing that can hold roles and act. Thing, group and actor are overlapping capabilities of one object, not kinds. A thing has this capability by having role secrets (spec/crypto.md §3).
  - A **key actor** (node, recovery key, link key) also has a signing key committed by its tid and owns itself.
  - A **node** is a key actor whose seed never leaves it.
  - An **account** is the actor apps treat as a user, team, bot or shared identity; its nodes hold roles on it (by app convention its owner is a recovery key and its nodes are its admins).
- **Ownership**: every thing but an ownerless one has exactly one owner actor, fixed by its creation record. An actor is a thing, so it has an owner too.
  - Owner chains end at a key actor or an ownerless thing (the chain's **top**), within `MAX_OWNER_DEPTH` owner links.
  - A delta written on a thing further below its top (judged from the creation records alone) is invalid, its `created.0` excepted; the rest of its commit is judged as usual.
- **Ownerless thing**: a thing whose creation record names no owner and no key but its **first admin** (spec/wire.md §3). It is an actor.
  - **Record edge**: its record gives the first admin an admin edge on it from before every edge write (the walk's initial state, §5.1; not an edge write: it applies by the tid alone and audits nothing). Edge writes change or remove it like any edge.
  - Nobody holds owner-chain authority on it: its admins are edges only, all equal, and may remove each other.
  - On a thing below it by ownership, owner-chain authority comes from being an admin of an actor on the chain, the ownerless thing included.
  - It has no roster snapshot (§6).
  - With no admin left, its edges, secrets and keys change no more (holders keep reading and writing as granted) and nothing recovers it.
  - Its **creation commit** carries its `created.0`, its first secrets (§3) and its `keys.0`, written as the first admin's write (an author with admin on that actor, or the actor itself), and puts the first admin's edge in `roles.0` (an entry for removals to reset, spec/crdt.md §5.6).
- **Role grant**: a record (holder actor, target, role), stored in the target's `roles.0`. On an actor it grants the role on everything the actor owns; on a plain thing, on that thing only.
- **Effective role** of a node on a thing at time t: the maximum over paths from the node to the thing of the minimum role along the path, evaluated with the timeline (§5.1) at t. A path climbs role grants and owner links (an owner holds admin on what it owns; an ownerless thing's record edge is a role grant while it stands); an actor holds admin on itself.
- **Admin** = write + change role grants + purge (§7) + write admin-only (`^`) aspects (spec/data-model.md §2; §5.2). An admin grant on a plain thing grants changing its role grants and purge on that thing.
- An actor's owner is implicitly its admin and cannot be removed by other admins. Other admins are equal and may remove each other.
- An edge write whose holder is its target or its target's owner actor is not applied (§5.1), and a roster snapshot's entry for either is ignored (§6).
- The role-class aspects of a thing (spec/data-model.md §9) are written only by its admins, whatever other role a node holds, except invite grants, self-removals and finalizes (§2), and what rotations and re-seals write into `secrets.0` and `keys.0` (§3).
- An ephemeral thing (spec/data-model.md §1) has no role-class aspects: a node's role on it is its role on a new thing owned by the nearest durable thing on its owner chain. An ephemeral ownerless thing has none, so writes on it, and on things below it, are invalid. Ephemeral writes need the role the durable write would need.

## 2. Role grant writes
- **Edge writes**: granting, changing and removing a grant are writes to the target's `roles.0`, each in its own role commit (spec/commits.md §2), by a node with admin on the target (a finalize, below: with write).
  - A removal of an absent grant is an edge write too (a reset of the holder's entry).
  - A grant or change is remove + put: a reset of every entry of the holder the writer holds, live or not, and a new entry holding the whole grant (spec/crdt.md §5.6 `remove`, then `put` of an absent key).
  - A `roles.0` delta writing inside an entry it does not create is bad input (judged from the delta and its header: the entry's dot is outside the delta's own dots).
  - A reset names the write it ends: its entry's creation. A role commit with a removal (a write leaving the holder no grant for keys: none, or `until` 0) resetting an entry whose creation the reader does not hold applies none of its edge writes until that creation is held; a commit's edge writes apply together or not at all. A reset beside a put of a live grant for its key decides nothing (the put sets the grant) and is not waited for. Limit: one whose creation the reader never gets (before its epoch start, §6, and not kept) never applies there. A reset carrying another key than its entry's creation removes no grant (spec/crdt.md §5.6).
- A grant may carry `until: timestamp`: the grant counts as removed from `wall_ms(t) >= until`.
- **An `until` passing** is a loss (§3) the node judges by its own clock, with no role commit behind it. A node whose read access only an `until` ended (walked with every grant's time ahead, it has a role):
  - First hears out the labels it tracks whose closure holds a thing it would forget. For each such label, one of these holds: it has a pass ended with nothing outstanding at every host it is open at, and is open at one; or some host refuses it (stranded, or not admitted); or it has no host.
  - Meanwhile its writes from before the `until` go up (a host that already serves a later step refuses them), and a renewal held by then keeps its role.
  - Then it drops.
  - It drops anyway `LOST_HEARD_WAIT_MS` after it first found the role gone.
  - A role commit received beside the ended grant that does not itself end the role changes nothing of this. A removal, demotion or a grant written with `until` 0 (below) ends it at once; a finalize (below) counts as the `until` it finalizes.
- **Finalize**: a removal of another holder's grant carrying no frontier that is not a self-removal (below). It applies (§5.1) iff the grant is past its `until` at the removal's `ts` (as the timeline orders it: a renewal ordered before it counts, and the finalize then ends a superseded write and applies nothing) and its author holds write on the target and a role there at least the grant's (a timed admin grant needs an admin); else it applies nothing, whoever wrote it.
  - It is no explicit write: it audits nothing, so the removed holder's own timestamps still decide its writes (§5.1, §5.2).
  - It is the grant's departure for keys (spec/crypto.md §4) and carries its rotation (§3) like any removal; one finalize may remove several ended grants of one target (spec/commits.md §2).
  - It says keep or erase as its `until` would (§3, Keep: the default in force at the expiry's key).
  - A node with write on actor T holding a grant on T it may finalize, past its `until` by its own clock, MUST write the finalize before its next commit encrypting under T other than by sealing a box to T (spec/crypto.md §4). Lacking a current secret of a role it would rotate, it waits for a re-seal, as for any removal, encrypting nothing under T meanwhile.
- A removal says **keep or erase** (§3, Keep).
  - Its plain entry reset says erase.
  - Its entry reset with the grant written anew with `until` 0 (role read, no invite, no `tied`), gone at every clock, says keep, and is a removal all the same (§5.1, §6), in one commit with its rotation. A client writes `until` 0 for nothing else.
  - It says what its remover wants, or else what the thing's default says: `keep` of the `required.0^` setting in force (spec/commits.md §5), none erasing.
  - A self-removal says what its node wants, whatever the default.
  - A client removing a node from its account writes erase unless its user says otherwise, whatever the default.
  - A receiver reads what the removal says, never the default.
  - An invite grant gone when written does not apply (§5.1).
- A grant may carry `invite: role`, at most its role. A `roles.0` delta putting a value that breaks this or reads as no grant, in a role commit or a roster snapshot, is bad by itself (spec/commits.md §4), and so applies nothing, its entry resets included.
- A node's **effective invite** on T is the maximum over its paths to T of the minimum of the roles along the path before the last grant and that grant's invite.
- An **invite grant** adds a grant for an actor with no current grant on T (an expired grant counts as none), with role and invite at most the author's effective invite, and carries the grantee's boxes for those roles.
  - Its `secrets.0` aspect is one delta holding only new keyed entries (puts, spec/crdt.md §5.6: each entry's dot is created by that delta): boxes keyed to its grantees at or below each one's granted role and history boxes at or below the highest granted role, with no reset of the value, a field, a map or any entry. This is judged from the commit alone.
  - The exemption holds only where the commit puts a grant on that thing and every such put applies as an invite grant (§5.1; another write of the commit applying, such as a self-removal, gives none).
  - A `secrets.0` delta that breaks this gets no invite exemption and is judged like any `secrets.0` delta (the highest role it rotates or boxes, at least write, §3, §5.2).
  - The grant's write is judged on its own (§5.1).
  - Invite holders cannot change or remove any other edge.
- **Self-removal**: a node with admin on actor X may always remove X's grant on any target, or lower its role, invite or `until`. Such a write is a self-removal when either holds; otherwise it is an explicit demotion (§5.1):
  - it lowers the author's own grant. Lowers: removes it, or sets no component of role, invite and `until` above the grant's value. An unchanged rewrite and a removal of an absent grant lower; `tied` is ignored.
  - admin on X is the author's only authority for it (no owner-chain or edge-admin authority on the target at that point, through X included).
- A self-removal needs no authority on the target and carries no rotation (§3); otherwise it is judged and audited like any edge write (§5.1).
- **Tied grants**: a grant whose holder is a group G (a thing with `group.0`) may carry `tied`: the `group.0` element of G placing the target T (as an item or subgroup) that the grant goes with, named by its creation stamp (spec/crdt.md §2.2) and its set.
  - The tie is no authority: edge writes are judged as without it (§5.1), a roster snapshot carries it, a change of the grant other than a new one keeps it.
  - A tied grant is written by a node that may make the grant and write on G, in the same local operation as the placement and after it, naming a live element placing T there.
  - A node that holds a current tied grant (G, T) and holds its element dead in G's `group.0` (an element record without a live value, or none under an effective reset above its creation stamp, spec/crdt.md §4.2, §5.5) MUST remove the edge when it may: as an explicit demotion when it has admin on T, after a complete pass (§3) of every label holding a thing of the demotion's pre-sync scope (§5.3) that ended after the last role commit of G or T it applied from elsewhere; else as a self-removal when it has admin on G.
  - An element it does not hold is dead only when it holds the element's own commit (§5.2) invalid for that delta; otherwise it is no reason to remove.
  - Only that direction: an untied grant stays when the placement goes, and a placement without a grant re-grants nothing.
- **Placing a lowered grant**:
  - A removal of another actor G's grant, and a self-removal lowering it, is placed by its author, as a certificate copy (§4) of every delta but its `secrets.0` and `keys.0` deltas, under every label holding G that the author syncs.
  - A node that applied a write lowering G's grant on a thing in the closure of G's label, which G's grant there has not been raised again since, places it under that label as a certificate copy of its `roles.0` and `tenures.0` deltas, with its author's chain, unless entries there hold them. Another node's write received less than `SETTLE_MS` ago is its author's to place (§4).
- A write that grants, changes or removes a grant whose holder is actor G MUST also be delivered to G as an inbox blob (spec/sync.md §3), so G's admins know what G holds roles on and erase what G lost.
- The roster apps read from `roles.0` is the role timeline's roster (§5.1), not the CRDT join of the stored deltas.

## 3. Secrets and rotation
- Each role secret of an actor is sealed to every holder of that role or higher, every epoch (spec/crypto.md §4).
- An ownerless thing has secrets of its own from its creation commit (§1): a rotation of all three roles from no epoch (spec/crypto.md §4), boxed to its first admin alone, with a deposit seed. It never has derived secrets. A creation commit by a node other than the first admin is delivered to that actor as an inbox blob (spec/sync.md §3).
- A plain thing uses derived role secrets until it gets a non-owner holder. It then gets random secrets of its own by a rotation from the derived epochs (spec/crypto.md §3), boxed to its owner and each holder, and a `keys.0`.
  - A thing that is to be granted a role on anything gets secrets of its own first.
  - An admin node that sees a current non-owner holder of a plain thing (left so by its only keyset part turning invalid, spec/crypto.md §3) SHOULD give it secrets of its own the same way, boxing every current holder, deciding at the end of a complete sync pass (below) of the labels of the actor its secrets derive from. Concurrent ones fork (spec/crypto.md §4).
- **Required rotation**: a departure (spec/crypto.md §4: removal, demotion, finalize) of holder M from actor A (a node removal is one, on the account) requires rotating every role secret M could open through A:
  - on A, the roles M left;
  - on every thing with secrets of its own that A's roles open (what A owns, the targets of A's grants, and so on transitively), the roles A holds there among those the roles M left open through A (a role secret opens only boxes of that role, spec/crypto.md §4). Those rotations are required through A's keyset: A's rotation lists the keyset M could open, so each box to A at it is stale (spec/crypto.md §4, Holder actors), and so on up.
  - Content is not re-encrypted.
- The write by another node that removes or demotes M on A and the rotation of A's roles it requires are one role commit (spec/commits.md §2). A node may hold its parts at different times (spec/commits.md §4).
- A self-removal (§2) carries no rotation: the departure stays uncovered until the next node that may rotate does so.
- Every other rotation is required of whoever may make it, when it next encrypts under the secret (spec/crypto.md §4). Nobody is required to sync anything to find it.
- **Who rotates**: a node with effective role write or above on an actor may rotate its roles at or below that role (a writer rotates read and write, an admin all three); through a holder actor only by showing it holds that actor's keyset secret (spec/crypto.md §4, Possession).
  - A rotation seals the new secrets to every current holder of each rotated role, writes the history boxes and the rotated roles' keysets in `keys.0` (spec/crypto.md §3, §4). The other roles keep their epochs.
  - A rotation boxing a holder that holds no box at a current read epoch before it, as the rotator's applied state stands, is also delivered to that holder as an inbox blob (spec/sync.md §3; to a node, over a direct connection).
  - Its validity is the author's role at its `ts` (§5.2) and possession (spec/crypto.md §4, Authority): a rotation, or a removal of a box to a holder actor its author holds a role on, counts the author's role through a holder actor only where it boxes it with a signature by the keyset it boxes at.
  - A `secrets.0` delta needs at least write and, per entry record it carries (a put, a write into an entry, a removal), the role its key names (a record acts only on the entry of its key, spec/crdt.md §5.6, so this is judged from the delta alone). A key-erased record, a key that is no box or history key, and a write or reset of the whole value or of a field need admin.
  - A `keys.0` delta needs write when it touches only the `read` and `write` fields, and admin when it touches any other field or writes or resets the whole value.
- A node that may rotate a required rotation MUST do so before it next encrypts under a secret it would replace; it MAY rotate eagerly.
- Sealing to a holder actor M's keyset is encrypting under M's epoch (spec/crypto.md §4): a node about to rotate, grant or re-seal A first makes the rotations of its holder actors it is required to make, so A's boxes name their new keysets.
- **Lockout recovery**: a writer can rotate read and write of A and box only itself, leaving every other node without a current secret (such a node makes no rotation, so no removal, spec/crypto.md §4).
  - An admin recovers by removing or demoting it with a frontier that leaves out its rotation commits whose epochs the admin cannot open (§5.1, an omission on purpose). Those turn invalid, their epochs are not established, the epochs they superseded are current again, and the admin rotates from those in the same commit.
  - It works only where that demotion audits the rotator (§5.1 step 4: its class on A falls); a client fails rather than stamp one that does not.
- **Holder actors** (spec/crypto.md §4): a rotation of A (a removal's included), a grant on A or a re-seal boxes a holder actor M at the keyset Seal gives, per role, or leaves it out of that role and the roles above until one exists (then re-sealed, below), or, while M's anchors fork, waits for M's merge. A departure from M or below it is M's to rotate for: it reaches A's boxes only as M's new keyset, which makes them stale.
  - A grant that would leave a holder actor with key access out of every role is refused.
- **Role cycles**: actors each holding a role on the next, back to the first, form a cycle. No key cycle forms: the grant that would close one is keyless (spec/crypto.md §4, Key access), so its holder reads nothing of the target through it.
  - A node that lacks the earlier grant takes the later one as giving key access and boxes into a cycle. Its box is stale (tainted) at every node that holds both grants, which rotates; until the writer holds the grants and the commits of the cycle, a device removed from one actor on it may read the other's new content (spec/requirements.md, Permissions).
- **Re-seal**: a node that may rotate a role may write a current holder's boxes for that role's current epochs, to the holder's newest keyset it holds (a holder actor: the keyset Seal gives, spec/crypto.md §4) and with those epochs' history boxes, changing nothing else (spec/crypto.md §4).
  - It is delivered as an inbox blob (spec/sync.md §3; to a node, over a direct connection, spec/sync.md §2) and placed under the actor's labels like any role commit.
  - A node that may rotate r SHOULD re-seal a current holder of r that it sees without a box at a current epoch of r, or whose heartbeat reports it stranded (§4), before it next writes under the actor.
  - **Complete pass**: it decides at the end of a complete sync pass of the actor's labels: one that read the log of every host, and of every peer it received the label from, can reach and that still reads it, to its end. A node MAY stop waiting for peers a bounded time after the role change it decides on (policy).
  - It re-seals never an actor without key access or a holder actor Seal leaves out (above), and only at established epochs (spec/crypto.md §4).
  - It re-seals for a role only when holding the secret of such a current epoch the holder lacks a box at. It boxes the ones it holds; another holder boxes the rest.
- **Label role keys** (spec/sync.md §2) derive from the newest epoch of each role; only an admin registers them. An admin issues the next step when it next syncs that label there, after uploading the rotation commits it registers (spec/sync.md §5), when either holds:
  - it holds an epoch newer than a host's head;
  - its actor's deposit seed derives a deposit key other than the head's, and it has opened every entry it can open under the label at the hosts it reaches and holds no unapplied `keys.0` write of the actor signed by a current admin of it.
- A host serves a label only to holders of its current sync key or of a claim key in its current step (spec/sync.md §5). A holder that missed rotations claims its way through the steps it missed, then downloads them and opens each under the epoch before it (spec/crypto.md §5), or is re-sealed (a claim set dropped on the way, or a rotation compacted, strands it until then).
- A node that removes a holder, a node included, MUST, in the same sync and before any other upload, place the removal and the affected actors' new `keys.0` under every label it tracks that the removed party could read (as certificates, §4).
- **Lost access**: a node that learns it lost read access to an actor MUST drop those role secrets and every local unit it can no longer read by another path, except what it keeps (Keep, below).
  - A held pending role commit boxing the node secrets of the actor (or of one a role on which gives one on it) is no loss of access only if either holds:
    - the node holds no secret of the actor but those kept for reading (learned only from pending or invalid commits, spec/crypto.md §4);
    - the commit is signed by its author, who holds admin or an invite on its actor as the node sees it now, and its `ts` is less than `PENDING_GRANT_WAIT_MS` before now (and not more than `MAX_DRIFT` ahead).
  - Whatever its `ts`, such a signed commit that boxes the node a read epoch newer than every one it held keeps its boxes through the drop (it may still apply and then gives the node the secrets with the role). The node reads nothing from them before it applies. Boxes only at epochs it held are dropped.
  - A held redemption (a commit removing its signer's own grant on a thing beside a grant there) granting the node, that stands void only because an applied redemption by the same signer removed that grant first, with no explicit write on that grant since (an unfinalized single-use link race, §8), is no loss yet: the node keeps what that grant would give and keeps syncing its labels until such a write arrives.
  - A node that lost read access through its own self-removal (§2) drops once that commit is placed (spec/sync.md §5, Placed), so it can place it (above).
  - One that lost it by an `until` passing alone (a finalize counting as its `until`) drops as §2 says.
- **Keep**: a node that lost read access to actor A keeps a read-only copy of A's things when one of its ways to A keeps.
  - A **way** is a holder H of A, in one of these forms:
    - a grant of H on A that ended saying keep, the node holding a role on H just before the write that last changed it;
    - a grant of H on A alive;
    - H owning A.
  - An ended grant says what the last write on it on the timeline (§5.1, the writes that applied) says:
    - a removal, for itself (§2; a roster snapshot's grant with `until` 0 being a removal saying keep, §6);
    - a value with another `until`, passed: the thing's default in force at its key (first `ts` at `until`, the zero tid and commit ID, or the write's key if later).
  - It keeps only while the node has H: it is H, holds a role on H now, or keeps H itself (least fixpoint, so holders cannot keep each other).
  - Everything else erases: a removal saying so, no default, a write that did not apply. A default set later changes no removal or ending before it.
  - **The copy** is what the node held when it dropped: state, bodies and their timers.
    - Its secrets and `secrets.0` go as above, and so does what it held of the things' labels: it syncs none of them, uploads and serves nothing of it, and cannot write it.
    - Its pending parts on the things' content go. A later part on it is not joined, so a purge request arriving later reaches the copy only in a commit the node takes for another part, and need not.
    - Certificate material stays and updates as on any forgotten thing (§4). Validity still follows what the node holds (§5.2).
    - Expiry and the keep bounds (spec/commits.md §5) run as on any held body. No body of a copy is must-hold, or known to anyone (spec/sync.md §6).
    - An actor the node acts as for a client (spec/sync.md §10) reads the copy while it is a holder the copy hangs on, or holds a role now both on the actor owning it and on such a holder, a holder that is itself a copy counting by its own holders. It writes nothing there.
  - The node records per copy the holders it keeps through, durably.
    - A holder leaves that record when the timeline shows its way no longer keeps (as above) or the node no longer has it. A copy with none is erased as lost.
    - A later roster snapshot changes nothing recorded.
    - A default arriving late may end a copy whose way is an `until` ending, once the node next judges that way and it then says erase; it brings none back.
    - A role on A with a secret of it again ends the copy: the node is a holder with old data, nothing more.
    - The node's user may erase a copy at any time, with what is kept only through it.

## 4. Verifying authors: certificates
- A write's authority is checked through the chain from the signing node up: each link is an edge write, an owner link (tid commits to the owner) or an ownerless thing's record edge (tid commits to its first admin), ending at a key actor whose tid commits to its public key. No secrets are needed.
- **Chain certificates** of a node for a thing are built on the things on any path from the node to the thing over owner links and every edge any held edge write, roster or ledger tenure sets, at any time, applied or not. They are:
  - for each such thing, its `created.0` record (and its owners' up to the top of its chain);
  - for each such thing, every held roster snapshot of it (§6, projected to the entries of holders among those things);
  - for each such actor, its **current `keys.0` commits**: its newest `keys.0` commit and the rotation commits of its newest keyset of each role, forks included, each projected to `keys.0` (the newest may write no keyset, and a rotation of what the actor holds names its keyset, spec/crypto.md §4);
  - every held edge write on a grant between two of those things (projected to its grant deltas);
  - closed under authors: for each such write, its author's chain certificates for its target and for its holder, and for each such snapshot, its author's for its thing.
- A node's **node card**: its `keys.0`, `node.0` and `reach.0` commits (each a commit of its own touching nothing else). The node card itself is never re-placed unchanged.
- **Placing**: when a node first places anything under a label, and whenever they change, it places its chain certificates (for the label's group and for each actor it has acted for) and node card under that label (spec/sync.md §3; a non-writer of the label by deposit), except the deltas an entry under the label already holds:
  - a certificate copy or closure blob placed by any node counts once the node has opened it as the same commit and checked each of its deltas against the header's delta hash (spec/commits.md §4), while it is present at every host the node syncs the label with;
  - a blob of a rotation commit of the label's actor (wrapped under the epoch it supersedes, spec/crypto.md §5) counts only if it opens under the newest read epoch.
- Deltas on things in the label's closure go as closure blobs, never as copies.
- A demotion or `keys.0` write by another node is its author's to place (§3); a node MAY wait up to `SETTLE_MS` after receiving one before copying it.
- A promoter completes the chain it holds: a writer promotes a deposited commit only once its author's chain for it is under the label, placing the missing parts itself (spec/sync.md §5).
- **`reach.0`** goes under every label by default; an app MAY exclude labels (e.g. public or bearer-read ones). A node that excludes a label already holding its current `reach.0` SHOULD rotate it: a new dialable key and lan secret, no longer listening with the old key, the new `reach.0` placed only where not excluded.
- **Heartbeat**: a node MAY place under a label it tracks a commit writing `seen.0` on its node thing (`{ ts: the commit's ts, stranded: bool, suspect }`), a non-writer by deposit.
  - Its `expires` is no earlier than `HEARTBEAT_MIN_LIFETIME` and no later than `HEARTBEAT_MAX_LIFETIME` after `ts`.
  - A node places at most one per `HEARTBEAT_MIN_INTERVAL` per label.
  - It MUST place one with `stranded: true` when it cannot read the label's current epoch: it reached the head and after a complete pass there cannot open the epoch it registers, or a claim on the way was refused (spec/sync.md §5).
  - A stranded heartbeat is wrapped under the newest established read secret the node holds (spec/crypto.md §5) and signed by the deposit key the host's head registers, as far as the node knows that head. A node whose held deposit seed of the label's actor does not derive that key places none.
  - The live heartbeat of a node under L (the newest `seen.0` commit received under L, not the aspect's joined read) gives its last sync of L; absent means unknown.
  - Heartbeats are never promoted (spec/sync.md §5).
- **Suspect**: a node flags an aspect suspect when:
  - a write of it turns invalid or valid while the node holds a body of it dropped for its keep bounds (spec/commits.md §5);
  - a body of it dropped as covered counts as never received (§5.2);
  - a part of it pending at its expiry goes (spec/commits.md §5).
  - A flag names the bodies it is about. An entry goes as its body is held again (or with its thing).
  - An entry not about a part that went pending at its expiry is dormant while a held compaction snapshot of the aspect valid at the node is stamped after the body's commit, judged from what the node holds when it reports (a snapshot turned invalid gives nothing, §5.2, so what it had settled is suspect again). An entry about such a part is never dormant.
- **Suspect list**: a heartbeat under L lists in `suspect` the flagged aspects of things in L's closure, at most `MAX_HEARTBEAT_SUSPECTS`, the most recently flagged first, each as `{ thing, ak, digest }`.
  - `digest` is the state digest (spec/crypto.md §6) under the thing's dedup secret.
  - The state bytes are the canonical CBOR array `[snapshot delta bytes, [page*]]` of the aspect's state encoded as a snapshot delta (spec/crdt.md §8) with an all-zero nonce, no frontiers or `Absorbed`, its pages in the order of their hashes, or no bytes for an aspect holding no state.
  - An aspect with no known creation record is left out until it has one.
  - A reader reads a node's suspect list from its live heartbeat under L (that commit's `seen.0` part, not the aspect's joined read); the repair it asks for is spec/sync.md §7.
- **Placing revokes**: any node that syncs a label and holds a revoke or roster snapshot about the author of an entry under that label that it judges invalid, or cannot judge yet, places it there (a non-writer by deposit), with the chain certificates of that commit's own author, of the `keys.0` commits only those of actors that read the label's actor. A revoke changes no verdict on the writes its frontier covers, so it is not placed for those alone.
- The grantee's current `keys.0` commits go under the target's label as a certificate, so every admin can seal and list the grantee.
- A commit's **author's chain** is its author's chain certificates for each thing it has a delta on and for its actor (§5.2, Acting). A commit whose author's chain to the things it writes has not arrived is pending (spec/commits.md §4); one whose chain to its actor has not is invalid until it arrives.
- A node that does not sync a thing applies the certificate deltas it holds; its timeline for that thing runs over the entries it was given.

## 5. Validity
Validity is a deterministic function of the commits a node holds.

### 5.1 Layer 1: role timeline
The timeline covers **edge writes**: writes to `roles.0` and roster snapshots. Every other role-class write (`secrets.0`, `keys.0`, `label.0`) is judged like content (§5.2) by the role its aspect requires (§1, §3).
1. Order all held edge writes, over every thing, by (`ts`, author node, commit ID). For each thing, start at its epoch start (§6) if it has one, ignoring its edge writes other than snapshots ordered before it; else at its first held write, an ownerless thing with its record edge in force (§1).
2. Walk the writes, skipping the drop set D (initially empty). A write applies iff its author has the required authority at that point:
   - admin on the thing;
   - for an invite grant, the effective invite it needs;
   - for a self-removal (§2), admin on the grant's holder;
   - for a finalize (§2), its own rule there;
   - a write lowering another holder's edge by an author that also has owner-chain or edge-admin authority on the thing is an explicit write of that class (step 3).
   - An **explicit write** is an applied edge write attributed to owner-chain or edge-admin authority (step 3), grants and raises included; self-removals, finalizes and invite grants are not.
   - Authority at a point is evaluated over every thing's state at that point, so the walk is one joint computation.
3. Attribute each applied write by X on N to X's **authority class** on N at that point: owner chain, edge admin, or invite (with its level); owner chain before edge, admin before invite. A finalize is attributed to no class. A self-removal (§2) through admin on actor M ≠ X counts as a write by X on M, attributed to X's class on M; one lowering X's own edge is attributed to X's class on its target (none, for a node with no class there).
4. An applied write R at time T **demotes** X on N when X's effective class on N (the maximum over all its paths) falls: from the owner chain, from edge admin to below, or to a lower invite level.
   - R then adds to D every earlier applied edge write by X on N, and, when N is an actor, on everything below N by ownership (transitively) where X's class also falls, attributed to a class X fell through (above its class after R, up to its class before R) and not covered by R's **frontier**, and the walk restarts.
   - Losing a path while another keeps the class is no fall: removing X's admin edge on N while X keeps the owner chain audits nothing, and X's later removal from the chain audits its edge-admin writes too.
   - **Edge as restored**: an explicit write on grant (M, T) judges X's class before it with the edge as restored: the join (componentwise maximum, alive) of the grant's values since the last explicit write on it, values taken away by `until`, self-removal or finalize included, plus, for X, the standing it kept as the author of an earlier explicit write on that grant (below).
   - R never demotes its own author: an author that is or reaches the holder (by owner links and edges alive just before R) keeps the standing the edge as restored for it gave it, even when R writes it unchanged, until the next explicit write on that edge, which audits it against the edge as restored.
   - Each edge write of a commit is judged on its own, against the state before the commit. The commit's applied edge writes then take effect one at a time in order (the header's aspect order, then by holder tid, bytewise); each write's demotions and whether its author reaches the holder just before it are judged with the earlier ones in effect.
5. A walk that adds nothing to D has settled; the timeline is the settled walk of the final round of §6. D is rebuilt from scratch whenever the held set changes.

- **Frontier**: R embeds what its author A had received of X's writes as of T on the aspects R puts in question in the settled walk with R and that frontier, as commit IDs, never counters.
  - **Aspects in question**:
    - for any demotion, role-class and admin-only aspects (spec/data-model.md §2), also of the targets of X's self-removals through things where X's class falls;
    - for a demotion below write, every aspect of the things the demoted authority gave write on.
  - **Listed**, each only as A had received it as of T:
    - X's commits with a delta on those aspects;
    - for a demotion below write, also X's held commits acting for one of those things (§5.2, Acting);
    - the role commits and roster snapshots among A's chain certificates for R's target (§4).
  - **Covered commits**: A MAY leave out a commit when A holds or dropped every delta its header lists and each of its deltas on those aspects (for a commit acting for one of those things, each delta but `created.0`) is one A dropped as covered or one A's compaction would drop now (spec/sync.md §7: covered by a snapshot A holds valid, purgeable by A, its keep-at-least bound `MAX_DRIFT` past on A's clock), when A had received every such snapshot (and, for a delta dropped as covered, every snapshot that covered it or covered such a snapshot dropped in turn) as of T.
  - **Purge requests**: for any demotion A also lists every commit whose purge request's right may rest on X's standing there (§7), received as of T, and none of those is left out as covered. Such a commit is both:
    - signed, as author or as the header's actor, by X or by a holder X's possible admins named with write or above on X;
    - naming a delta on a thing whose role-class aspects R puts in question for X or on which such a thing may hold write.
  - Only where a frontier would pass the list bound a node resolves does A leave out the purge-request commits it received last, as few as fit, each then losing its right.
  - **Omission on purpose**: A MAY also leave out a received commit on purpose. Receivers judge by the frontier alone, so such an omission is A's repudiation of those writes, made by a client only as an explicit act (§3, Lockout recovery).
  - A lists no ephemeral commit.
  - A write is covered iff its commit's ID is listed.
  - **Received**: a commit counts as received once A decrypted its header and verified its signature (the header pins its deltas by hash), whether or not A holds, applies or stores its deltas; relaying is not receiving.
  - A frontier MUST NOT list a commit A had not received as of T.
  - Besides R itself, nothing but the frontier decides what X's writes before T survive: a write on A's chain that the frontier does not list is audited like any other.
  - A frontier above `CHUNK_THRESHOLD` is a chunked large value referenced by link (spec/commits.md §1).
- A demotion by `until`, self-removal or finalize audits nothing. The next explicit write on that grant, by any node, audits with its frontier against the edge as restored.

### 5.2 Layer 2: content
- A delta is judged by its author node's authority, whatever its header actor (Acting, below, adds a condition). A delta by X on thing N is valid if X held write or above on N just before the commit's key (§6; grants' `until` judged at its `ts`) and no valid explicit demotion of X below write on N is ordered after it (a ledger entry with a frontier counts as an explicit demotion at its key, §6).
  - An **explicit demotion of X below write on N** is an applied explicit write (§5.1 step 2) by another author, or a ledger entry with a frontier, that demotes X on N (§5.1 step 4) and takes X's role on N, with the edge as restored, from write or above to below write.
- Otherwise it is valid iff the frontier of X's newest valid explicit demotion below write on N (ledger entries included) lists its commit.
- A `secrets.0` delta of a role commit other than a compaction snapshot (which copies others' boxes) is also judged by possession (spec/crypto.md §4, Holder actors, Authority): a rotation or removal whose author's role on the actor comes only through holder actors it shows no possession of makes it invalid.
- A delta of an **admin-only** aspect (AK marker `^`, spec/data-model.md §2) is judged by the two rules above with admin in place of write: X held admin on N, demotions below admin. A writer that does not hold admin on N MUST NOT write one; every node judges it alike from the AK alone, also on an ephemeral commit's part and a compaction snapshot's delta.
- A delta breaking the required retention in force at its key (spec/commits.md §5) is invalid, whatever the rules above say. A `required.0^` delta is judged by those rules as an admin-only delta; where it turns invalid or valid, every later delta on its thing is judged again.
- **Compaction snapshot**: a snapshot S's delta of an aspect is judged as its author's delta of that aspect by the rules above, at S's key, needing the strictest role a write it could carry needs (admin for `label.0`, `keys.0`, `secrets.0` and admin-only aspects, else write). `created.0` is always valid.
  - An invalid S gives nothing: its body joins nothing, covers nothing (spec/commits.md §5).
  - A valid S vouches for every write it carries: no carried write is judged as its claimed author's.
- **A write's own commit** is the one holding it on that aspect: for a session-form write, the commit whose range holds its dot; for a commit-form one (source `Commit(C)`), C.
- **Copies**: a held valid snapshot's copies count wherever held, also where the receiver received the write's own delta (a node attributes a write's author and time only to a commit it holds and verified).
- **Misstates**: a snapshot misstates a delta when it carries a write under one of the delta's dots that the delta does not hold at the same position with the same stamp and payload. These count as misstating:
  - a dot the delta does not use;
  - another `ts`, position or value;
  - a value-less copy, unless the delta has an expiry;
  - a list element's reset at its creation's own stamp (spec/crdt.md §4.7).
  - A deleted text element's copy without its char is no misstatement.
- Where the receiver holds that delta's body and a held valid snapshot misstates it, the delta's writes under that dot count for nothing and the valid snapshots' copies join by the copy order (spec/crdt.md §4.1). The receiver SHOULD report each snapshot misstating it other than by value-less copies (a diagnostic).
- Otherwise the delta's writes count while it is valid. An invalid delta's writes are un-merged (spec/crdt.md §4.6), and the held valid snapshots' copies of them stay, as the snapshots' writes with the payload they carry (a copy of a deleted text element's creation without its char never gives the char).
- A record carrying no `ts` (a tombstone, a bare anchor) carries no write.
- **A valid snapshot's body dropped** leaves what it gave in the state and vouches no more, except its misstatements of held deltas, which go (those deltas give their writes again).
- **When a held snapshot turns invalid**, or a copy of one whose body dropped while it was valid arrives again (spec/commits.md §5 Never received) and is judged invalid, what it gave goes: exactly those writes, and its records carrying no write, such as bare anchors, under the same dots. Others' writes nested under them stay; a record left with no write goes (spec/crdt.md §4.2).
  - The held deltas and the other held valid snapshots give their writes again.
  - The writes that go are those it carries under dots of deltas in these states (a copy placed otherwise, as in a map entry's key-erased record, spec/crdt.md §4.7, included):
    - held with their bodies;
    - never received;
    - dropped as covered, where every cover, followed through covers dropped as covered, is held with its body.
  - A write under a dot of a delta dropped otherwise, or of one whose covers include a snapshot dropped for its keep bounds, expiry or a purge (its writes are in the state alone), stays.
  - Each body of that aspect dropped as covered (compaction, spec/sync.md §7; not for its keep bounds, expiry or a purge) whose covers (the held valid snapshots that covered it when it dropped) none carries any more counts as never received from then on (as a body dropped for its keep bounds does, spec/commits.md §5, here with its writes). A coverer carries it if it is held with its body and valid, or dropped under covers one of which carries it. Such a body:
    - if a delta, its own writes go from the state (exactly those writes; the held valid snapshots give their copies again);
    - if a snapshot, gives nothing;
    - joins as a late part (spec/commits.md §4) when it arrives again.
- An actor holding the required role in the timeline's final state, every grant with an `until` counted as removed, is re-granted: each of its writes ordered at or after the first point it ever held that role is valid again, including those in the gap and those a demotion's frontier left out. Edge writes in the gap stay dropped.
- **Acting**: a commit whose header actor (spec/wire.md §4) is not its author is invalid, every delta and ephemeral part of it but `created.0` (whose record holds by its tid), unless a delta of its author on that actor needing write, at the commit's key, would be valid by the rules above (its demotions, frontiers and re-grant alike).
  - Role commits and roster snapshots act for their author, so the role timeline never depends on this.
- One dot names one write: two commits of one session with overlapping ranges on one aspect are both invalid (spec/commits.md §4).
- A delta that becomes invalid is un-merged (spec/crdt.md §4.6).
- **Ephemeral parts**: a part of an ephemeral commit (spec/commits.md §2) is judged as the durable part of its kind would be, at the commit's key, needing the aspect's role (§1; on an ephemeral thing, through its nearest durable owner):
  - a session-form one as its author's content delta;
  - a snapshot one as its author's compaction snapshot delta.
  - A part on a core aspect other than `placed.0~` (spec/data-model.md §9) is invalid.
  - A demotion's frontier lists no ephemeral commit, so an explicit demotion invalidates all the demoted node's ephemeral commits, its snapshots included. What a valid ephemeral snapshot carries it vouches for, as any snapshot does; one turned invalid gives nothing, and a body dropped as covered by it counts as never received, as for a durable snapshot. What becomes invalid is un-merged (spec/crdt.md §4.6).

### 5.3 Revoking (client behavior)
- Before stamping a role-lowering edge write a client SHOULD sync every label of every thing the demoted authority gave write on (found by walking the grants and `label.0` writes below), and take the write's `ts` after applying what it downloaded.
- A label of a group the client does not hold MAY instead be read for receipts only: its commit headers decrypted and verified (§5.1), nothing kept or applied but the role commits that give its secrets; while doing so the client MUST NOT upload, delete or place anything under that label or register a step there.
- When it cannot (a label unreachable, unopenable or too large, or the app will not wait) it SHOULD let the app choose between failing and stamping anyway; uncompacted writes by the demoted holder under the labels not synced are then lost (spec/requirements.md, Permissions).
- An explicitly backdated revoke skips this.

## 6. Roster snapshots
- A **roster snapshot** of thing N is a role commit with the roster-snapshot marker, by a node acting through N's owner chain (admin of N's owner actor or of an actor above it, or the key actor at the top; never by an edge on N). It has no frontier.
- An ownerless thing has no owner chain, so it has none: its `roles.0` and `tenures.0` are never compacted.
- **Contents**: reset-plus-full-state deltas of N's `roles.0` and `tenures.0` as the author's timeline computes them, one delta per grant and per ledger entry plus one per aspect carrying the reset alone (spec/commits.md §2).
  - A grant whose last write was a removal saying keep stays as that value; a removal saying erase names its holder in no grant.
  - A grant of role write or above also carries `since`, the key of the write that started its tenure in force (with none in force, of the write that set the grant), absent if unknown.
  - N's other role-class aspects are untouched: they compact like any aspect (spec/commits.md §2).
- A write's **key** is its position (`ts`, author node, commit ID) in the order of §5.1.
- An explicit write **audits** when the edge as restored (§5.1 step 4, a demoter's kept standing included) exceeds its new value: the new value is absent or expired when written, has a lower role or invite, or carries an `until`.
- **Tenure ledger** (`tenures.0`): one entry per tenure of role write or above on N that ended before S. An entry holds:
  - holder, role, `since` as above;
  - `until` = the key of the write that ended it. Any role change ends a tenure and, at write or above, starts one at the new role, so a demotion from admin to write ends an admin tenure and a promotion from write to admin a write tenure. An expiry by `until` has the key (first `ts` at `until`, the all-zero tid, the all-zero commit ID), and has an entry only once a later write on the grant is held: until then the expired grant stays in the roster with its `until`;
  - when that write was an explicit demotion that audited (§5.1 step 4), its frontier (inline or by link; empty if it carried none), else none.
  - An explicit write on the holder's grant that audits while no tenure of it is in force (after an end by `until` or self-removal, or the standing its demoter kept, §5.1) is an entry of its own: `since` = `until` = its key, the highest role it audits, its frontier.
  - An explicit write that audits from above the role of the tenure in force ends that tenure, which goes on from its key.
  - An entry with a frontier stands for an explicit demotion by `until`'s node at that key.
  - The previous epoch start's ledger is carried forward whole; entries are never dropped.
- **Epoch starts** are chosen for all things together, in rounds. T is the number of things with a held roster snapshot that takes part in the walk (not one kept out of the walk, below). The first round, and the first after each restart, has no starts.
  1. A round walks the timeline (§5.1, D from scratch) under the current starts until D settles.
  2. In that walk every held snapshot S of N is judged at its position (its key), whether or not it is N's start and whether or not it is ordered before N's start. S applies iff it is not in D and its author has owner-chain authority on N at that point. An applied S is an edge write on N attributed to the owner-chain class, so a later demotion of its author may add it to D (§5.1 step 4). Only N's start changes N's edges; an applied S that is not the start changes none.
  3. After the round, N's new start is its newest snapshot (by key) that applied in the settled walk and is not excluded. N has none if no such snapshot exists.
  4. If the new starts equal the current ones for every thing, they are the epoch starts and that walk is the timeline.
  5. Otherwise, if this round is round T+1 since the last restart (or since the first round), every snapshot that is a start in exactly one of the current and the new starts is excluded and the rounds restart; else the next round runs under the new starts.
  6. An excluded snapshot is never chosen as a start again in this evaluation; it is still judged, attributed and audited in every walk.
- **Under an epoch start S of N**:
  - N's edge writes ordered before S are ignored (N's snapshots are not).
  - At S's position N's grants become S's roster, whether or not S itself applies.
  - In the walk, a value of S's roster or ledger takes effect at its key, just after the commit that key names (whose edge writes on N are ignored).
  - S's roster and ledger answer what role anyone held on N before S: a holder held a role at a point inside one of its ledger tenures of that role, or after its roster grant's `since` and after every ledger tenure of its own. A roster grant or ledger tenure without `since` counts from the beginning.
  - Each ledger entry with a frontier takes part in the walk (§5.1) as the explicit demotion of the holder's grant it records, so edge writes made through N before it are audited as that demotion audited them.
  - A demotion of X after S audits X's writes before S too, including those under tenures without a frontier.
- A linked frontier's tree blobs MUST be in the commit's chunk list, its value MUST be a `frontier`, and the distinct linked frontiers of one snapshot (by content hash) MUST total at most `MAX_LINKED_FRONTIERS` canonical bytes.
  - A `tenures.0` delta whose link is not listed or whose value is no `frontier` is bad input by itself (spec/commits.md §4).
  - S takes no part in the walk on N while any of these holds, a function of its deltas and blobs held, whichever came first:
    - a held `tenures.0` delta of it on N waits for a linked frontier's blobs;
    - its held deltas name one holder on N twice in `roles.0` deltas;
    - on every thing it has deltas on, its held linked frontiers exceed that total.
  - Its held deltas stay applied and the holders they name stay named (spec/commits.md §4).
  - A writer refuses a snapshot that would so take no part in the walk.
- A certificate copy of S carries the grant and ledger deltas the verifier needs and the reset-only deltas (spec/sync.md §3); its signed header still shows a co-reader the roster's and ledger's sizes (one delta hash per grant and entry) and the number of linked frontier chunks.
- S replaces N's earlier `roles.0` and `tenures.0` deltas (their writes die at S's `ts`); their retention keeps them at least `ROLE_KEEP` after that (spec/commits.md §5).

## 7. Purge rights
- **The right**: a delta's retention names who may purge it (spec/commits.md §5), judged at the request's time. Each member of the named set holds the right on its own:
  - **admin**: the thing's current admins;
  - **author**: the delta's header actor while it holds write on the thing: the actor itself and any node with write on that actor;
  - **writer**: any current writer of the thing.
  - An admin with no write on that actor holds no right under `author`, and an actor that lost write on the thing gives none until it regains it.
- A role counts toward the right exactly when a delta of its holder needing that role at the request's key would be valid (§5.2): a demotion whose frontier does not list the request takes the right however early its `ts`; one that lists it leaves the purge standing; a re-grant gives the right back to a request made in the gap, as to its writes.
- **A purge request** drops a named delta iff its author held that right at the request's time and, when it acts for another actor (its header actor), so did that actor. Each delta of a request by whole aspect or by author is judged alone, so the class of one never widens the others (an admin's request by author leaves that author's `author` and `nobody` deltas).
- **Judgment** follows the role timeline the node holds, in any arrival order:
  - A named delta a request comes to drop is dropped then.
  - A delta held as its leftover for a request when no held request drops it any more counts as never received (spec/commits.md §5): its leftover is set aside and it is no longer held value-less, the node fetches it again where present and takes it from a holder's upload (spec/sync.md §6).
  - A held body stripped for carrying a purged value (a snapshot, a delta carrying a copy, spec/crdt.md §4.7) counts as never received with any such fall (its stripped copy no longer joins) and is asked for again, and stripped again on arrival if it carries another's.
  - A body no node holds stays gone; the delta then reads as never received.
  - Held value-less again before a copy comes, it holds the leftover it set aside, as at a node that never saw the fall; a snapshot's part dropped as named stands in again (spec/commits.md §4) with no copy.
- **Who may undo a purge so**: the author of a demotion, whose frontier omits the request. A frontier may list a message and omit its purge, and the message is back wherever a copy is left. A memory delta vanished stays gone.
- A node deletes at hosts on its judgment after syncing, with no waiting time.
- The same right decides whether a compaction snapshot may drop a body it covers (spec/commits.md §5); a body a right holder dropped under a snapshot whose right later falls stays dropped.
- At hosts a delete key proves the right as of the delta and the label key current roles (spec/sync.md §5).
- **Without a right**: a node MAY drop:
  - a delta made invalid by a required retention (spec/commits.md §5) if, on its own record, it received the delta after the `required.0^` delta it breaks, so a change stamped below bodies a node already holds takes none of them;
  - a `required.0^` delta whose author is not a possible admin of the thing (spec/commits.md §4).
  - Nothing else goes without a right. A delta so dropped that turns valid counts as never received.
- What the right promises is that honest nodes keep the body. Which hosts carry it follows the thing's labels: a thing leaving a group leaves that label's hosts whatever its retention (spec/sync.md §6), and holders keep their copies.

## 8. Links
- A **link** consists of K, an actor owned by the sharer with secrets of its own, granted the link's role on the target, and L, a key actor whose seed is in the link, with a grant (role r, invite r) on K for the link's role r.
  - The sharer's actor is K's only admin.
  - A client making the link writes the target's `keep` default then in force on K (§3) when it says keep.
- **Link text** encodes: L's seed, the target tid, K's tid, K's label ID and host addresses, and optionally the sharer node's dialable key and relays.
- **First contact**: a redeemer sharing no host with the sharer dials the sharer's node at that key, which serves K's label as a co-reader peer (spec/wire.md §10).
  - A link carries only that key and those relays: holding it gives nobody the sharer's `reach.0` (the lan secret goes only to co-readers of labels its `reach.0` goes under, §4), and a sharer does not place its `reach.0` under K for the link's sake.
  - The redeemer dials that key with an ephemeral transport key and no co-reader proof (spec/sync.md §5, §10), opens K's label there as at a host, and MAY keep dialing it, from the link it followed, for K's labels and the target's, nothing else.
  - Putting the key in a link is the sharer's explicit choice, and a node without hosts can make only such links (one naming no host and no node reaches nobody); it serves K's label and the target's complete (spec/sync.md §5).
- **Rotating the dialable key**: when a link ends by revocation (of L, or with a joiner's), by expiry, or a multi-use link otherwise, the sharer SHOULD rotate its dialable key and lan secret; a single-use link finalized by its redemption does not.
- L is listed in every step of K's label by its static entry with an entry box (spec/sync.md §2), and holds boxes in K's `secrets.0` like any key-actor holder (sealed to L's KEM key, spec/crypto.md §3).
- **Redeem**:
  1. Derive L's keys from the seed.
  2. Claim K's label by L's static entry, take K's read secrets from the head's entry box (spec/sync.md §2), download K's label and L's boxes.
  3. Wait until the held role history shows K's grant on the target (a client making a link delivers that grant under K's label), and grant nothing without it: the target is the link text's word, unsigned.
  4. Then, signing as L, invite-grant the redeemer's actor (or a fresh node) to K with role r and seal K's secrets to it. L writes in commit form and deposits the commit under K's label (spec/sync.md §5) unless r is write or above.
  - A redeemer SHOULD discard the seed afterwards.
  - A rotation of K by a holder's departure (a joiner's leave, a node removal) changes nothing for the link: L stays a holder and the next step lists it.
  - The link has ended, and the redeemer stops there, when either holds:
    - every route of K's label (the link's hosts and node, as known) has failed to open it, at least one by refusing L's static entry;
    - a held role history shows L's grant, or K's on the target, removed or past `until`.
  - A redeemer that stops, for any reason, forgets the seed and so loses read access to K and what K holds (§3).
- `until` on L's grant expires the link. **Single use** (the link's `flags` bit 0, spec/wire.md §10) = the redemption also removes L's own grant in the same commit (a self-removal).
- **Finalized**: L's grant past `until` is finalized like any ended grant (§2), by any writer of K: that removal rotates K and audits nothing. Besides, an expired or self-removed L is finalized by a sharer node writing an explicit removal of L (§5.1), which audits L's invite grants: a node that holds the link's seed thing and admin on K MUST write it once L's edge expired or was self-removed (or finalized) with no explicit write on it since, after a complete pass of K's labels (§3) that ended, for an expiry, after `until` (when K's labels have no host, at once and only by the node that wrote the seed thing; with hosts it waits for that pass however long it takes).
  - An invite grant as L that the removal's frontier does not cover is dropped (§5.1 step 4); one received before it stands.
- The sharer's link seed thing is placed in the sharer's home group, so every node of the sharer holds it. A node removal does not end a link: the removed node reads through L until L is removed from K. An implementation MUST tell the one removing a node which of the account's links still work, and let any node of the sharer remove their L.
- **Bearer use**: act as L without writing anything. Read only. A node that read as L may forget the seed and keep what L reads and follow it (a contact card, spec/sync.md §3): it counts as read access while L holds a role on it (§3).
- A joiner that may still hold the seed is revoked only together with L, both removals in one commit with one rotation of K (spec/commits.md §2); a new link is a new L.
- The sharer keeps the seed on a thing only its own actor reads (the seed thing: aspect `link:seed.0`, a map {0: K's tid, 1: the seed, 2: the target's tid, 3: single use}) and writes L's `keys.0` and K's deposit seed.
- **Recovery card**: recovery key seed, account actor tid, home label, several host addresses (spec/wire.md §10). The recovery key owns the account actor, so every step of the home label lists it with an entry box. A node holding the card claims the home label's current step by the key's static entry (spec/sync.md §5), takes the read secret from the entry box, then its boxes, `label.0` and `created.0`.
