# Sync
> Summary: How nodes and hosts store and exchange blobs: labels, what goes under them, host operations and their authorization, the sync protocol and convergence rules, ephemeral commits, transports and bundles.

## 1. Blobs
- A **blob** is one of:
  - an encrypted commit (header plus unpurged deltas; spec/commits.md);
  - an encrypted chunk, tree node or page (spec/data-model.md §6, spec/crdt.md §8, a header list spec/commits.md §1);
  - an inbox blob (§3).
- Hosts cannot tell them apart except as §4 states.
- **Layout**: **clear prefix** || ciphertext. The prefix holds a salt, an optional expiry `T`, the blob's **class** and the delete-key commitments, one per level (spec/crypto.md §7). Ciphertext: spec/crypto.md §5. Bytes, padding, **Blob ID** and the `MAX_BLOB` bound: spec/wire.md §5.
- **Class**: durable, ephemeral or relay-only, set as spec/wire.md §5 states. Hosts hold ephemeral entries in memory only and relay-only ones not at all (§4, §5).
- **Several blobs of one commit**: one commit may travel as several blobs (purge rewrites, certificate copies, concurrent re-encryptions): same header and commit ID, each with its own key, salt and ID.
- **Prefix of a commit encryption**: every encryption of a commit computes its prefix from the header and the aspects its sections list (spec/wire.md §4):
  - expiry = the commit's `expires`;
  - one commitment group per distinct delete-key set among those aspects, blinded by the new salt (spec/crypto.md §7; spec/wire.md §5);
  - a header-only blob (spec/commits.md §5) has neither.
- **Chunk reuse**: a chunk reused by a later delta keeps its blob and prefix, unless it must be re-encrypted.
  - It is re-encrypted when one of these holds:
    - its expiry is earlier than the new delta's;
    - its commitments to the thing's delete keys (levels 1 and 3) are not exactly those of the keys the reusing delta lists;
    - it commits to a level-2 key other than the reusing delta's, and that delta lists no level-2 key or only a level-2 key.
  - Beside a level-1 or level-3 key an author-chain commitment need not match.
- **Repair** of a chunk or tree node blob:
  - A node repairs the blob when all of these hold:
    - a held, unexpired delta of the node's own commit links the blob through its large values' trees;
    - every host of a label it syncs has deleted the blob (a purger that had not seen the reuse);
    - the node may write the aspect and holds the blob.
  - To repair, it writes each large position of the aspect's current value whose tree holds the blob again, whole and without a reset (`put_new`, spec/crdt.md §5.6), reusing every other chunk and re-encrypting that blob, with that delta's retention and expiry.
  - How often is local policy.

## 2. Labels
- A synced group has a **label**: the unit a host stores. A label has an **index** i (0 for a group's first label) and the role keys below.
- **Role keys**: Ed25519 keys, the first three from the group thing's role secrets (explicit, or derived from its base actor's by tid; spec/crypto.md §3):
  - **sync** `kdf("label sync", read secret, le64(i))`;
  - **write** `kdf("label write", write secret, le64(i))`;
  - **delete** `kdf("label delete", admin secret, le64(i))`;
  - **deposit** `kdf("label deposit", deposit seed, label ID)`, from the deposit seed of the group's actor (§3; spec/crypto.md §3).
- **Label ID**: derived from the genesis delete public key (spec/wire.md §8). The genesis step derives from the admin secret current when the label is created.
- **Registration steps**: a tree. Layout, signature and **Step ID**: spec/wire.md §8.
  - A step holds: label ID, `prev` (the step ID of its parent; none in the genesis step), the four public keys (sync, write, delete, deposit), a fresh X25519 **step key**, BLAKE3 of the **claim set** (which holds the **entry boxes**), and a signature by the parent's delete key (the genesis step by its own).
  - Each step is carried with its claim set.
  - A host holds one path from the genesis step to its **head** (§4). A new step is a child of the target host's head (§5).
  - An admin MAY issue a step without a rotation (same role keys, fresh step key) to list readers granted since its parent, key actors in particular.
- **Claim set** of a step: padded with random keys to a power of two, in random order. It lists each **reader** M of the registered read epoch: every actor holding its read secret as the registrar knows it at registration (the holders of boxes carrying it, the owner included; of a plain group, its base actor (spec/crypto.md §3); a holder re-sealed later opens by sync key).
  - A reader is listed by its claim public key (derivation: spec/wire.md §8). M's X25519 key is the X25519 half of its read-role KEM key in the newest `keys.0` of M the registrar holds (a key actor: its single KEM key). A non-contributory DH result omits M.
  - A reader that is a key actor other than a node (a recovery key, a link key) is listed instead by its **static entry** (spec/wire.md §8), the same 32 bytes.
  - The registrar erases the step private key after signing.
  - M derives its claim key from its own private key and the step key; it tries each keyset epoch it has held.
- **Entry boxes** of a step: one for each reader that is a key actor other than a node (a recovery key, a link key), sealed to its KEM key (spec/crypto.md §4 sealed form; AD = (label ID, step key)). Layout: spec/wire.md §7.
  - It holds the epoch's read secret and, when the epoch supersedes one whose secret the registrar holds, the secret of the one with the greatest n, ties by lowest nonce (what its rotation commit is wrapped under, spec/crypto.md §5).
  - A key actor holding no secret of the group reads the label from the current step; the rotation commit's history box (spec/crypto.md §4) opens the rest.
  - Each secret names its epoch of the group thing (spec/crypto.md §4); it is held as that epoch's secret, which establishes nothing.
  - Other readers get none: they read the rotations they missed in order (spec/crypto.md §5), or a re-seal (§3).
- **Role keys in use**: a node talks to a host with the role keys of the epochs the host's head registers; it derives them from the matching epochs it holds (every holder holds all older secrets by the history boxes). A node whose epochs match no step the host holds opens under the sync key of the newest step it shares with the host and walks from there (§5).
- **`label.0`** on the group thing: `map<label ID, { index, steps: map<step ID, step>, hosts: list<address>, replaced: bool }>`. Role-class. An address: §10.
  - Each step is held with its claim set and entry boxes, which an admin MAY drop once the step has been superseded for `ROLE_KEEP` (counted from the `ts` of the write recording its first child).
  - Nodes upload under, and sync, every label of the group not marked replaced.
  - A `label.0` write on a group is also published under the home label of the nearest actor up the group's record chain that has one.
  - One role commit may carry the `label.0` deltas of many groups.
- **Replacement** of a label lost at a host:
  - An admin rotates the admin secret if the loss calls for it, creates label index `1 + max index in label.0`, uploads the live blobs under it and marks the old label replaced.
  - At hosts it still controls it deletes the old label's content entries, keeping its role commits and the `label.0` commit that marks it replaced.
  - No new step of a replaced label is issued. At a host that does not hold it, the admin MAY register its recorded path again to place that `label.0` commit there.
  - Once that commit is under the old label and its content entries are gone at a host (or the label cannot be opened there), the admin's work there is done.
- **Home label**: an actor with role secrets (not a key actor) MAY be synced as a group of itself; that label is its home label.
  - It MUST have one when it names it as its inbox or when it owns labeled groups or receives grants (below).
  - The home closure holds the actor thing and what its `group.0` lists, nothing by ownership.
  - A link's K label is K's home label.
- **Inbox**: the label an actor with role secrets names in `keys.0` for inbox blobs (§3): a label of a group its admins administer (by default its home label).
  - An actor that names none uses the inbox of the nearest actor up its record chain (spec/permissions.md §1) that names one, or an ownerless thing's own live label on the way, so its readers read those blobs.
  - Key actors have none: a node receives a direct grant only over a direct connection to the granting node (pairing); a recovery key or link key holds its label from its card or link and claims the current step by its static entry (§5).
- A thing in no labeled group is not synced. Only an admin's `label.0` write makes a label; a grant makes none.
- **Route**: a holder of a role on a thing reads it only through a live label it can open whose closure holds the thing (§3).
  - That label is either:
    - the thing's own label (every holder of a role on it derives its sync key); or
    - a label of a group whose closure holds it, whose actor may read it, and whose actor the holder may read or which reads the holder (a subgroup holder's readers read through the group).
  - A grant records the role whether or not the holder has a route. Without one it holds the role and reads nothing until a label carries the thing (the first label of a thing is delivered to its holders, §3).
  - A link's K reads its target's own label alone, so making a link gives its target one if it has none.

## 3. What goes under a label
- **Closure**: the blobs of group G are the commits touching any thing in G's transitive closure (through `group.0` and `ephemeral_group.0~`, spec/data-model.md §8: an ephemeral membership brings its item's ephemeral commits), plus the chunk, tree-node and page blobs they reference (every blob their values link, whether or not the linking commit's chunk list names it).
  - Each node tags commits with their things' `groups.0` and retags when group membership changes.
- **Entitlement**: a thing's **reader actor** is the thing if it has secrets of its own, else the nearest actor up its record chain that has them (a key actor is its own). G's actor is the group thing if it has secrets of its own, else its base actor (spec/crypto.md §3). G's actor may read a thing iff the thing's secrets derive from its own or it holds read or above on the thing's reader actor. A commit's blob belongs under G's label iff G's actor may read a part of it on a thing of the closure (or published there, §2).
  - Only a writer of G stamps entries (§5).
  - A node that is not one deposits what it must place there (its chain certificates and node card, its invite grant or self-removal, its heartbeats, and the revokes it must place by spec/permissions.md §4) and relays stamped entries it holds.
- **One blob per commit**: a commit is uploaded as one blob holding every part of it the uploader holds and can seal, each part in the section of its thing under the thing's read secret (spec/wire.md §4; a part of a thing whose read secret the uploader lacks, a key actor's own record or card, travels as a certificate copy). Every label of every thing the commit touches carries the one blob under its label's wrap; hosts and nodes syncing several of those labels dedup it by blob ID. No size split: a commit stays within `MAX_BLOB` by paging its deltas (spec/crdt.md §8), largest first, or is refused at the writer.
  - A node judges a blob by the parts the label's actor may read (§6); a section it cannot open it copies verbatim when it encrypts the commit again (a tombstoned entry, a purge rewrite).
  - A section opens with the thing's read secret at the epoch the writer used: a reader of the thing holds it (its own, through its history boxes; a plain thing's by derivation through the record chain the section lists from a member it holds epochs of), and a holder of a role on the thing's reader actor keeps up with its rotations through a label carrying it (§2 Route).
  - **Per-label copies**: besides certificate copies (below), a label whose readers could not open a part's section in the shared blob gets a fresh blob of the parts its actor may read, one section under the read secret of the label's group, never shared with another label; judged like any body of the commit. Exactly two cases: a role commit with such a part on a thing other than the label's actor (its boxes are what give the readers that thing's secrets: a rotation, a grant, a cross-published `label.0`, §2); a part on a thing whose read secret derives from neither the label's actor nor an actor in its closure (a cross-published `created.0`, §2; a thing added from another actor's tree, read by role on a reader actor whose rotations the label does not carry). A blob a node opens only under the label group's secret for a section on another thing is such a copy: its sections are not copied into another encryption.
- **Retag**: when a thing joins a group, any writer of the label that holds the thing's live blobs adds them under it; when it leaves, delete-key holders delete them under the old label as they see the change (§7).
- **Certificate blobs**: chain certificates, node cards, heartbeats and revokes (spec/permissions.md §4): copies of the parts of a role commit about one actor.
  - They go under a label as a fresh encryption per label, never as a blob shared with another label.
  - The chunk and tree-node blobs of a linked frontier or header list go under it too, as the same blobs (a link names them) with a filler wrap.
  - A writer promoting a deposited commit completes its author's chain under the label from what it holds (§5).
- **Inbox blob** (spec/crypto.md §5; layout and payload spec/wire.md §9): the parts about actor G of a role commit, boxed to G, with the label IDs and host addresses of those things it names that have labels of their own.
  - **What it carries about G**, any of:
    - a grant with G's boxes;
    - a change or removal of G's grant;
    - a re-seal of G;
    - a rotation boxing G where G held no box at the read epoch before it;
    - the `label.0` write giving a thing G holds a grant on its first live label: sent by its writer to every actor on the thing's roster that is not a key actor and whose read keyset and inbox it knows.
  - **Placement**: under G's inbox (§2) by deposit, or by upload when the sender holds the inbox label's write key. The inbox group's admins may delete it earlier than its expiry.
  - **Re-send**: its prefix expiry is `INBOX_LIFETIME`, after which the sender re-sends unless the recipient has since acted on it: a commit by it or a node of it writing a thing the blob names or a thing such a thing owns. Acting elsewhere does not count. A sender MAY bound the number of re-sends.
  - **Stamping in place**: a writer of the inbox's group stamps a deposited inbox blob in place (§5).
    - It does so when either:
      - its commit is applied, valid in every part the blob carries, and about an actor whose inbox the label is (it has parts a copy below would take for that actor); or
      - its user declined it (below).
    - It does not when another blob of that commit under the label is stamped, or the blob's prefix expiry is more than `INBOX_LIFETIME + 2 × MAX_DRIFT` ahead of the corrected clock.
    - A blob so stamped leaves the deposit budget and stays readable until it expires.
    - Every other inbox blob stays deposited, until it expires or is cleared (§5).
  - **Following a payload label**: the payload's labels and hosts are the sender's word. A recipient follows (opens, dials the hosts of) a payload label only:
    - while the blob is unexpired and its commit is applied or pending and not judged invalid;
    - for a thing it knows no label of, whose read secret the commit gave it (a `secrets.0` delta valid, or pending with a box that opens);
    - for a label no `label.0` it has applied records;
    - at most one per blob;
    - never at a `peer://` address.
- **Label hints**: the label an inbox blob names is its sender's word until a `label.0` the node holds records it.
  - Blobs naming one label under different things are tried in turn: under the first thing not failed since the label's last retry, at the hosts all of them name, each retried after `resync_ms`.
  - A hinted open by a sync key holds only at a head of that key, whatever the host answers.
  - What a connection delivers under a label is read under the thing the label is opened under on that connection; elsewhere a label belongs to the group whose held `label.0` records it.
- **Invite requests**: a recipient node applies the commit of an opened inbox blob, and follows what it names, only once it **admits** the blob.
  - It admits the blob when either:
    - the commit is already held (applied or pending; a sibling node that accepted it places its copy under the home label); or
    - its sender is **connected**: the header's author is a key actor whose creation record the node holds and under whose key the commit's signature verifies, and the author has an effective role now (spec/permissions.md §1, as this node judges it) on a group the node syncs (§2), on a thing up such a group's record chain, or on an account whose contact card the node imported.
  - A blob not admitted is an invite request: its commit is not applied, its chain certificates (spec/wire.md §9) are not ingested, and nothing it names is fetched, followed or dialed until the user accepts it.
  - It is judged again as the node's state changes.
  - Accepting admits it.
  - Declining one leaves its commit unapplied, at that node and for good, from every inbox blob carrying it. The same commit arriving in a blob under a label the node syncs (a sibling node that accepted it placed its copy under home) is applied as any commit: the acceptance wins.
- **Grant copy**: a grantee node that accepts a grant for an actor (from the inbox, from K's label, or by pairing) places a certificate copy of the grant, with the `label.0` commits of the labels it reached, under that actor's home label; not when an entry there already holds the grant's parts, counted as for chain certificates (spec/permissions.md §4).
  - From an inbox blob only a node with admin on the actor copies, and only, of a valid applied role commit:
    - the carried parts on the things where a `roles.0` delta writes the grant of the actor or an actor it owns or a `secrets.0` delta boxes one, or, of a `label.0` write, on the named things where the actor or an actor it owns holds a grant;
    - with the `created.0` commit and every `label.0` commit of those things that the payload names (no `label.0` commit of a thing the actor reads no more);
    - and the author's chain of each (spec/permissions.md §4), that chain without any `keys.0` but its author's own;
    - and nothing from a blob whose expiry is less than `INBOX_LIFETIME` / 2 away.
  - Nothing else an inbox blob carries is placed.
  - A node runs this whenever it opens an inbox blob, its commit held or not.
- **Inbox blob order**: a sender still opening or registering a label an inbox blob names at a host it is connected to, open at none of them, deposits the blob after that ends. A node told a label is unknown at a host, with no step of it to register, opens it again after a back-off of `retry_ms` doubling per refusal up to `resync_ms` (local policy).
- **Contact card**: a link (spec/permissions.md §7) with read role to an account's profile thing P, a group of itself with no items: its label carries P's own aspects and, as certificate copies, the account's `created.0` and `keys.0` commits.
- **Unjudged blobs**: a receiver keeps blobs a peer placed under a label even if its own closure disagrees, while it cannot judge them: a commit it holds pending (not parked) or an entry of the label it can open and has not applied; then §6 decides.

## 4. Host state
Per label:
- **Registration path**: the steps from the genesis step to its **head**: every step's role keys, step key, `prev` and signature; each step's claim set and entry boxes until it has been superseded for `ROLE_KEEP`, longer by policy.
- **Entries**: blob ID; wrap or, for chunk/tree/page and inbox blobs, a random filler; stamp or none; deposited flag; optional pending deletion time.
- **Tombstones** (blob ID) of deleted entries, kept `TOMBSTONE_LIFETIME`.
- **Log**: an append-only log of events (entries added, deletions, registrations) with sequence numbers, trimmed up to the position of every durable entry removed (deleted or expired) `TOMBSTONE_LIFETIME` ago, and further at the host's choice (a cursor below the trim gets Error 15, §6).

Across labels:
- Blob bytes are stored once per host and deleted when no label references them.
- Ephemeral entries, their log events and their tombstones are held in memory only and lost at a restart. No sequence number handed out before a restart is handed out again.
- Relay-only blobs are never held.

## 5. Operations and authorization
Each operation names a label. Writes are signed with the role keys of the host's head; reads need the label opened on the connection:
- **Open** (sync key or claim key): a signature under `"osis v1 label open"` over (label ID, the host's connection challenge from the handshake, its static key). Opens the label on that connection for download, specific-blob fetch, reconciliation and subscription.
  - A sync key is matched against the head first, then against the newest superseded step on the path bearing it (a step without a rotation shares its parent's keys).
  - A signature under a superseded step's sync key is answered with that step's child on the path (without its claim set) and nothing else. The client verifies it under the step's delete key before using it.
  - An open holds under the sync key of the head it was made at (by a claim or static entry too). Once the head is a step with another sync key, the host ends it on that connection with the label's subscription (the last push carries that head's event, §8) and answers its reads 8 until the label is opened again.
  - A co-reader proof's open is not tied to steps.
  - A client whose open head gains a child with another sync key (its own registration included) opens again.
- **Claim**: an open signature under a key V, with (step ID j, V).
  - If V is in step j's claim set: j the head opens the label, j on the path is answered with its child as above. Otherwise refused like an unknown key.
  - A key actor other than a node sends its signing public key with the open signature instead of (j, V), only to labels of things it holds a role on or that it follows for itself (its link's or card's label). The host opens the label if its static entry is in the head's set, and that key reads the current read secret from the head's entry box.
  - A holder that missed n steps walks them in n round trips, verifying each step under its parent's delete key (the genesis step against the label ID), then downloads the rotations and derives the current keys. The claim is bootstrap only.
  - A claim at a step whose set the host has dropped is refused; such a holder places a stranded heartbeat (spec/permissions.md §4) and is reached only by re-seal (spec/permissions.md §3).
- **Register** (delete key of the parent). Relayable by any node.
  - Accept a genesis step only if its delete key hashes to the label ID and the label is new.
  - Accept a step whose `prev` is the head.
  - Otherwise refuse anything else (a step with another `prev`, an operation under keys of a step it does not hold) with code 9 and nothing more (other codes: spec/wire.md §11.2). A refused registration never carries the head (a registrar learns it by opening).
  - A step is registered with its claim set when the registrar holds it (it MUST hash to the step's). A step held without its set serves no claims at it.
  - **Storage caps**: a step and its claim set count toward the label's and the host's storage caps (the claim set until it is dropped, §4). Past them:
    - a new label's genesis step is refused (code 12);
    - a child step is accepted without its claim set (it serves no claims);
    - a child step past them even without its set is accepted at most once per label per a policy interval (host policy, non-zero), else refused (code 12), and never refused for a cap otherwise.
  - **Refused for now**: a registrar keeps its open on a step refused for now (codes 4, 12, 14) and registers it again later. A path a host refuses for now (codes 4, 12, 14: the rate, a full host, a label it does not admit yet) is registered again after a back-off (local policy, bounded), never at once.
- **Stamp**: a signature under the label's write key, domain `"osis v1 upload"` (spec/crypto.md §2), over (label ID, blob ID, wrap). A host checks it against the write key of its head; stamps already accepted stay valid across re-registration.
- **Upload** (stamp; no open needed): add entries, each with wrap and stamp.
  - Anyone holding a stamped entry may relay it, hosts included (replication between hosts is push only: download needs an open).
  - Refused: a bad stamp; a blob whose prefix expiry has passed; a blob ID with a tombstone; an oversized blob; an ephemeral blob past the label's ephemeral cap (code 12).
  - An upload of a deposited entry's blob ID replaces its wrap and stamp and clears its deposited flag.
  - A stamped entry's wrap and stamp never change while it lives: an upload of its blob ID is answered OK, changes nothing and logs no event, as does a deposit of a held blob ID.
- **Relay-only** upload: the blob is not stored. It is pushed to the label's subscribers on the host's other connections (spec/wire.md §11.2) and leaves no entry, log event, tombstone or expiry.
  - Refused:
    - without an expiry or with one more than `2 × MAX_DRIFT` ahead (code 1);
    - at or past its expiry (code 7);
    - above `MAX_RELAY_BLOB` (code 3);
    - past the label's relay rate (code 4).
  - A host pushes a blob ID once per label until its expiry (a repeat is answered OK and pushed to nobody), remembering a bounded number of them (past it the earliest-expiring is forgotten).
- **Replace**: an uploaded entry may name entries it replaces (spec/wire.md §11.2), each with the signatures a Delete of it (without a time) would carry, except that one commitment group signed for suffices (a rewrite by a right holder of one of its things).
  - The host checks every one it holds first (named entries it does not hold are skipped unchecked): a refused signature refuses the entry (codes 1, 9) and changes nothing.
  - The entry is admitted as an upload is, counting toward its caps the room the replaced entries it holds would free (an entry's room counts toward the cap of its own kind: durable or ephemeral).
  - Admitted, it is logged first, then each replaced entry it holds is removed as a Delete removes it. Refused, nothing is removed.
  - Named entries not held are skipped, as is the entry itself.
  - A relay-only entry naming any is refused (code 1).
  - Removals by signature count toward a delete rate limit as deletes do.
- **Wraps at a node**:
  - **Node holding the blob's key**: it takes only a wrap opening to that key. An entry a host holds stamped, under any step's write key, under any other wrap counts as lacking at that host (§6) for as long as the host holds it. A wrap opening under no read secret held counts so only until a read secret arrives under which it opens to the blob's key.
  - **Node holding no key**: it keeps its wrap unless one of these holds:
    - the new one opens under a held read secret and its own does not;
    - its own opened to a key the blob refused;
    - neither opens and the new one is stamped and its own is not.
  - At a node holding no key, an entry stamped at a host under a wrap that does not open while the node's own does counts as lacking there.
  - At a node holding no key, when a new wrap that opens replaces another, entries at the hosts that gave the other count as lacking there too.
- **Deposit** (deposit key): add one entry with the given wrap (filler for an inbox blob) and no stamp, flagged deposited in the log.
  - Refused like an upload, when the label's deposit budget is full, or for an ephemeral or relay-only blob (code 1).
  - **Budget**: host policy, with a recommended minimum (spec/wire.md §2). An entry leaves the budget when stamped, deleted or expired. The reply reports the remaining budget only to a deposit whose signature verifies under the head's deposit key.
  - A deposit whose signature does not verify (code 1, or 9 under an earlier deposit key) and one under an unknown label learn the code alone, neither budget nor head.
  - **Sending**: a client sends a deposit of its own write (sealed, wrapped and signed when made) to each host of the label until that host answers it, also after losing read access to the label's actor (spec/permissions.md §3).
  - **Refused for now** (unknown label, rate limited, budget full, storage cap, an Error reply) is no answer: the deposit is sent again after a back-off (local policy, bounded; a deposit the host takes ends the back-off of the client's others at that host and label) until the host takes it or it is moot.
  - **Refused as signed by an earlier deposit key**: signed again with the current one, or dropped when the client holds no other.
  - **Moot**: an inbox blob once its delivery is forgotten or sealed again (§3), any deposit under a label the client sees replaced.
  - **Promotion**: a writer that verifies a deposited commit the label must hold re-uploads it stamped (promotes it), only once its author's chain for the deposited deltas (spec/permissions.md §4) is under the label.
    - A promoter completes the chain it holds, placing the missing deltas as its own certificate copies with the promotion.
    - A writer that holds neither the commit applied nor the chain leaves the deposit unpromoted.
    - The author's chain under a label leaves out every `keys.0` but the author's own.
    - A certificate copy is never deleted for an incomplete chain.
    - A heartbeat (spec/permissions.md §4) is never promoted.
- **Clearing an inbox**: a node holding the delete key of an inbox label (§2) keeps at most `INBOX_WAITING` entries and `INBOX_WAITING_BYTES` bytes per host of the deposits there it can do nothing with.
  - Those are every deposited entry except:
    - one it opened as a commit under a read secret (parked included);
    - an inbox blob it would stamp (§3);
    - an inbox blob whose commit is pending and whose prefix expiry is within `INBOX_LIFETIME + 2 × MAX_DRIFT`.
  - Past either bound it deletes them at each pass, in this order:
    1. all but opened invite requests (§3) with a prefix expiry within that bound, those with no expiry or a later one before the rest, then earliest to expire first;
    2. then those requests, earliest to expire first.
- **Placed**: a commit a node made is placed when each label it syncs of the things the commit touches holds the parts of it the label's actor reads that it must hold (§6) in an entry present at one of its hosts, not counting as lacking there (above), or covered by a snapshot there (a label with no host: in an entry the node serves; skipped when the node has no `reach.0`). Copies of it elsewhere (certificate copies, inbox blobs) do not wait for it (spec/commits.md §4).
- **Delete**: by the delete key, or of one entry by delete keys of levels: one delete signature per commitment group of the blob's prefix, each verifying under that group's commitment at its level (spec/crypto.md §7; one signature may cover several groups committing to the same key), plus a signature under the head's write key when any level is 3 (thing write secret), else its sync key; any other is refused. An empty group (a `nobody` delta's) is never covered: such a blob goes by the delete key, at its expiry, or by Replace.
  - Optionally **timed**: the entry is removed at the given time instead of now (one pending time per entry, the earliest request wins).
  - Removal leaves a tombstone for `TOMBSTONE_LIFETIME`.
- **Expiry**: at the prefix's `T` the host deletes the entry outright: no tombstone.
- **Download**, specific-blob fetch, reconciliation (§6) and subscription (§8): only for labels opened on the connection; a blob is fetched by ID only as an entry of an opened label.
- **Host caps**: hosts cap storage per label and the memory of ephemeral entries per label (and in total), counting each entry's, log record's and tombstone's overhead besides its blob.
  - An ephemeral upload past its cap is refused (code 12).
  - At the total cap the label using most gives way: its oldest log records, then its oldest entries, deleted with a log record and no tombstone.
  - An ephemeral entry's tombstone lasts `MAX_DRIFT` (in memory).
  - Hosts may rate-limit deletes, deposits, registrations (code 4) and relay-only uploads per label.
  - A cursor below a trimmed ephemeral log gets the live ephemeral entries added since in place of their add events.
- **Co-reader peer**: A co-reader peer serving a label applies the same rule (relay-only uploads included: it passes a new one on to the label's hosts it syncs with, §9).
  - It may also serve a node of a current co-reader: an open whose proof is a signature under `"osis v1 co-reader open"` (spec/wire.md §11.2, proof 3) by the `dialable` key of a `reach.0` it holds on a node thing whose actor currently reads the label, where no other node thing's `reach.0` it holds names that key. Hosts refuse such proofs.
  - A co-reader peer that syncs a label with no host serves it as its own host:
    - it issues a child step when it would re-register at a host (recorded in `label.0`);
    - it holds the bodies it holds that the label must hold (§6) and the blobs they link, its certificates and heartbeats, and the inbox blobs it sends to an inbox label it syncs with no host;
    - it drops what its sync would delete at a host (a body with live writes only once a carrier is under the label) or what expired.
    - A body past its keep-at-most bound (spec/commits.md §5) is dropped all the same: that bound wins, and a node that may not write the aspect writes no carrier.
- **Re-registration**: an admin node that holds the epochs a host's head registers (the write and admin ones established) and, for any role, an established epoch newer than the head's (spec/crypto.md §4; its own rotation or another node's) issues a child of that head when it next syncs that label at that host.
  - Order, at that host:
    1. it uploads, under the head's keys, the role commits of the actor the label's keys derive from (§2) that it holds and the host lacks (the rotation commits of the epochs it registers and of those they supersede in particular);
    2. it registers;
    3. it uploads anything else (a remover does so in the removal's sync, spec/permissions.md §3), and records the steps in `label.0`.
  - While that host refuses the step for now (Register), the admin's uploads and deletions there go on under the host's head (wrapped under the newest read epoch as always, spec/crypto.md §5).
  - An admin that does not hold the head's epochs walks and reads first (§2) and registers nothing.
- **Reading without the head's read epoch**: a node holding no secret of the read epoch a host's head registers fetches and opens every entry present there whose wrap opens under a read secret it holds, again whenever it gains one (an entry listed before was not fetched then). Only after that does its pass there count as complete (spec/permissions.md §4, stranded).
- **Deletion by delete key**: a node holding a delete key for a body the label must not hold (§6) deletes it under every label it syncs as soon as it sees the condition. Whichever delete-key holder sees a valid purge executes it.

## 6. Protocol
- **Framing**: framed messages over an ordered byte stream (§10); version negotiation, messages and limits: spec/wire.md §11. Every message has a fixed maximum size; every list is paged.
- **Handshake and clock**: each side's handshake carries its wall clock (ms) and a random challenge for opens (§5).
  - A node SHOULD estimate its clock offset from peers' handshakes and Ping/Pong round trips (spec/wire.md §11; round-trip corrected, robust to an outlier, ignoring samples whose round trip exceeds a few seconds) and use the corrected clock wherever wall time is used.
  - A node SHOULD close a connection on which requests are outstanding and nothing moved for minutes (no byte received, none of its own taken by the transport), and redial.
- **Flow control**:
  - **Requester**: it keeps at most `WINDOW` in flight per connection, counting per request sent and not answered its frame length plus a reply allowance:
    - `MAX_MESSAGE` for Reconcile;
    - its `max_reply` for a Sync, Fetch, Call or Sub (spec/wire.md §11.2);
    - `SMALL_REPLY` for every other kind.
    - It sends the next request while below `WINDOW` (so one always goes), in the order it made them.
  - **Pushes**: a peer sends a push (§8) only while its bytes not yet taken by the transport on that connection, the push included, stay within `REPLY_BUDGET`, or none are. Otherwise the subscription's pushes wait (Notifies likewise), continuing from its position once they fit (held subscriptions in turn, so none starves another), and a relay-only entry that does not fit is not pushed on that connection.
  - **Closing**: a peer MUST NOT close a connection over unwritten bytes below `WINDOW + 2 × (MAX_MESSAGE + 4)`, and MAY close one beyond it.
  - **Unanswered requests**: count the frame lengths plus allowances of the requests a peer receives before it has answered any of them. A peer MAY close a connection whose count passes `WINDOW + 2 × MAX_MESSAGE + 4` before it answers them, without running the request that passes it.
- **Cursor sync**: a client keeps a cursor per (peer, label) and sends: the cursor, its own new blobs inline, and the blob IDs it gained under that label from other sources since. The peer replies with its log after the cursor minus those IDs, blobs inline, and a want-list of the gained IDs it lacks, which the client then sends.
- **First sync** of a label at a peer, from no cursor:
  - The node lists it (Sync with `inline_limit` 0, to its end) and then fetches every listed entry it lacks, in the order of the wraps (spec/crypto.md §5):
    1. order 0, and at the node's own inbox label what does not open;
    2. then the highest order first;
    3. last what does not open, ranked again as secrets arrive.
  - Order 0 goes before anything else is asked. How many are asked at a time is local policy.
  - A body not fetched yet is one not received (spec/commits.md §4).
  - A node runs passes once order 0 is here.
  - An entry that opens and is not here keeps what it would settle unsettled, as an unopened entry does, except that the node's own commits count as established uncovered (no snapshot covers what only it has sent), so it sends its own writes; it runs no repair (§7).
  - The pass ends, and the cursor stands at the listing's end, when nothing is left to fetch. A node that stopped part way (a restart, a lost connection) goes on from what it listed, without listing again.
- **Range reconciliation** (fallback when a cursor is missing or invalid, or the gained list exceeds a message): range-based set reconciliation over the IDs of the live entries (additive fingerprints, 16-way splits; spec/wire.md §11.3).
  - After a cursor the peer's log was trimmed past (Error 15), an entry the client knew present there that the peer lacks was deleted there, as by a deletion event.
  - After any other fallback it is only not present there.
- One connection may sync many labels; a blob under several of them SHOULD cross it once (spec/wire.md §11).
- **Convergence**: a label's **required set** is its closure blobs (§3) plus what is placed there from outside the closure:
  - the certificate blobs of spec/permissions.md §4, judged by the deltas a blob holds, whatever else its commit writes (a `created.0` copy of a commit that also placed the thing);
  - the grantee's certificate copies and cross-published `label.0` commits (§3);
  - unexpired inbox blobs.

  Per node, a body it holds is **must-hold**, **must-not-hold** or **may-hold** at a label. A body meeting a must-not-hold condition is must-not-hold whatever else holds of it.
  - A delta is **kept** while it is before its keep-at-least bound or under `nobody`, and its keep-at-most bound (if any) is more than `MAX_DRIFT` ahead on the node's corrected clock.
  - **must-hold**: in the required set and, for a closure body, one of:
    - a delta of it kept;
    - established uncovered: the node can join it and no held snapshot of the aspect under the label that is not a carrier only covers it (spec/commits.md §5).
  - **Header-only blob**: in the required set only as the lasting header of a commit lasting on a thing of the closure whose actor the label's reads (spec/commits.md §5), with no other body of the commit wanted there, and then is must-hold, whatever snapshot covers it. One of a commit with a permanent delta or a purge request that is not lasting here is may-hold: another node may judge it lasting.
  - **must-not-hold**, any of:
    - purged;
    - expired (its blob's prefix expiry, §3, whatever of it the label's actor reads);
    - past keep-at-most;
    - dropped without a right (spec/permissions.md §6);
    - outside the required set;
    - a blob of commit C whose delta set is a strict subset of another held blob of C under that label that is not itself must-not-hold and whose extra deltas include one only a blob carries: kept or holding a live write, and covered by no snapshot under the label;
    - another node's node-card commit (spec/permissions.md §4) once a later valid card commit of that node writing the same aspect is under the label (an entry of it this node opened and checked against its header);
    - another node's node-card commit, for `node.0` and `reach.0`, once that node reads the label's actor no more after an applied edge write on its way to the actor ended a grant (removed it, or its `until` passed).
  - **may-hold**: the rest: covered, between bounds, parked, unfetched pages, a certificate blob whose author has no other blob under the label.

  After syncing:
  - **Writer**: uploads every must-hold body the label lacks, as a fresh encryption if the old blob ID is tombstoned or its entry counts as lacking there (§5). A blob of the commit that is not must-not-hold and holds every delta of the body that no snapshot under the label covers holds it.
  - **Reader**: relays the stamped must-hold entries it holds that the label lacks.
  - **Neither** uploads nor relays a body a delete removed from the label (an entry of it that is not a certificate copy, within `TOMBSTONE_LIFETIME`) while both of these hold:
    - each of its deltas only a blob carries (as for a strict subset above) is held there by another blob of the commit that is not must-not-hold;
    - no held purge request signed by ones that could hold the right (spec/commits.md §4) names a delta of it without dropping it (spec/permissions.md §6).
    - So once a delete or a bad Replace took a delta covered by a snapshot under the label, no one places it again, even a node that dates its deaths later (spec/commits.md §5) and still keeps it: the host keeps the snapshot's live state, not that delta's history before its keep-at-least bound. Once no valid snapshot under the label covers it, its holders place it again.
  - **Delete-key holders** delete must-not-hold bodies.
  - **Dropped bodies**: a node that dropped a body keeps knowing its entries (not its key or wrap). When the body counts as never received again (spec/permissions.md §5.2) it fetches them again where present, and otherwise takes the body from a holder's upload (it is must-hold there: no valid snapshot covers it).
  - **May-hold bodies**: nobody acts on them except a compactor dropping them once per body (commit and delta set, §7).
  - **Tombstones**: a tombstone only keeps the identical blob out, against stale relays and bundles.
- A partial node repeats reconciliation until a pass changes nothing, since newly received data may grow its closure.
- Chunk and tree-node blobs of large atomic values may be fetched lazily, by local policy; pages of a delta are fetched before its commit is applied (spec/commits.md §4).

## 7. Compaction and deletion
- **Compact**: a node that may write an aspect uploads snapshot commits (spec/commits.md §2) for the aspects it compacts, then drops, and deletes at hosts, the bodies they cover.
  - It drops and deletes a body only when all of these hold:
    - the snapshot is not a carrier only (spec/commits.md §5);
    - the snapshot's commit holds the right over the body (spec/commits.md §5);
    - it may purge the body;
    - the body's keep-at-least bound (spec/commits.md §5) is `MAX_DRIFT` past on its clock.
  - **Other right holders**: every right holder that holds a snapshot under the label, its author included whatever it wrote it for, does the same for its bodies, judging a body again while it is before that time or not established covered or uncovered.
  - **Live writes**: a body with live writes (in any of its deltas) is deleted at a label only while other entries under it carry each of them: a snapshot under the label covering it, or another blob of the commit holding it that is not must-not-hold and not an identical body with a higher blob ID (of two duplicates the higher goes without waiting).
  - **No carrier**: a right holder that must delete a body with live writes and finds no carrier uploads a covering snapshot first when it may write the aspect, unless it holds a blob of the commit that will carry them (a purge's rewrite).
    - A host refusing that blob, a strict subset of the body, for the label's cap (code 12): it is uploaded again naming the body as replaced (§5).
    - The snapshot-first order binds only drops that would leave a live write in no held blob (keep-at-most), not strict-subset or purge drops.
  - Chunk blobs still linked from a retained version are kept.
  - Two snapshots covering each other (equal `ts`, spec/commits.md §5) are covered-equal; a compactor drops the one with the higher commit ID.
- **Sweep**: before a snapshot of a durable content aspect (not role-class, not `required.0^`), a node resets, in one ordinary content commit, each map entry and list element (at any depth below live ones) that is not live (spec/crdt.md §5.6, §5.7) and holds a write beside its removal or an expiry or purge it holds of its creation.
  - A write here: in a map any write under a key, else a value-carrying one or `W`; a sequence's bare anchors are no write.
  - A record merely lacking its creation is left: the creation may arrive.
  - A reset so repeated stays if the first remover turns out invalid.
- **Repair**: a node that may write an aspect of a thing in a label's closure, past its first sync there (§6), acts on each entry of another node's live heartbeat under the label reporting it suspect (spec/permissions.md §4) whose digest differs from the node's own digest of that aspect, if it holds state of the aspect.
  - It writes a snapshot of the aspect from its whole state (spec/commits.md §2) and places it like any must-hold body, unless it already wrote one from that same state for that node.
  - It judges each entry of each heartbeat once.
  - It SHOULD report every entry it judged (a diagnostic), repaired or not.
- **Duplicates**: of two blobs of one commit with the same delta set under one label, a delete-key holder deletes the one with the higher blob ID. Of two at a host where one counts as lacking (§5), that one, and it counts as no copy of the other.
- **Eviction**: a partial node may evict bodies it does not serve. Live state is never lost: a node keeps it in its own state (spec/crdt.md §4.6) and a label in an entry (above); a co-reader peer serves current state from the bodies and snapshots it holds.

## 8. Subscriptions
A connection may subscribe to labels. The peer then pushes new log events (with blobs, wraps and stamps) as they arrive (held back for a slow subscriber, §6 Flow control), in the cursor-reply format, until the open ends (§5).

## 9. Ephemeral commits
- **Sending**: a node's own writes of ephemeral aspects and on drafts (spec/data-model.md §1, §2) are ephemeral commits (spec/commits.md §2) like its durable writes are durable commits.
  - **One commit**: a write's ephemeral writes are one session-form commit (without `expires` under the node's session, with one under its second session, spec/crdt.md §2.1), carrying the records of the drafts it writes or its `ephemeral_group.0~` writes add (spec/commits.md §2), so a deletion's resets ride with the removal that takes the thing out of the closure, as a durable commit's do.
  - **Second commit**: a durable write's own consequences in memory (a persisted thing's memberships leaving `ephemeral_group.0~`, a durable removal's entry in `ephemeral_group.0~`, a deleted thing's ephemeral aspects; their revert) go as a second commit of that form, under the durable commit's `ts`. The two are separate commits: a peer may hold either alone.
  - **Signals**: a write's signal writes go as one relay-only commit, at once.
  - A commit whose delta does not fit a blob is refused at the writer (spec/commits.md §2).
- **As durable bodies**: an ephemeral commit's bodies are judged, placed, uploaded, relayed and deleted exactly as durable bodies are (§3, §5-§7): under the labels of the closures its things are in, must-hold while established uncovered, stamped under the head's write key at each upload (so a refusal under an older key, code 9, is answered by the next pass under the new head), relayed stamped by readers, deleted at a label once a snapshot there carries them, re-placed as a fresh encryption where the old blob is tombstoned.
  - A thing no closure holds syncs no more (§3): nothing of it goes anywhere, and its bodies under a label it left are deleted there like a durable thing's, by a node that held the body in that closure (after a start a node's view of the closure is what has arrived so far: it deletes nothing for being outside it).
  - **Storage**: what differs is storage and what follows from it. Every node holds ephemeral commits, their blobs and every record about them (entries, presence, tombstones, carriers) in memory only (Holding).
  - **Held at a host**: an entry counts as present at a host only as learned on the connection up now (a restarted host lost its ephemeral entries and its durable log says nothing of it). A node's first Sync of a label on a connection lists the ephemeral entries it holds there as `gained` (when they fit the message; §6), the peer asks for those it lacks, and the rest count as present there once the Sync ran through.
  - **After a start**: a node's first sync of a label at a host after it starts reconciles the live sets first and keeps its cursor (the entries the cursor passed are in no memory any more). A connection ending before every entry that reconciliation found missing was received reconciles again on the next.
  - **Tombstones**: an ephemeral entry's tombstone lasts `MAX_DRIFT`, at hosts (§5) and at nodes alike, and an announcement of a blob tombstoned here within that time is nothing.
- **Coalescing**: before a pass sends under a label, two or more of the node's own plain (no `expires`) session-form commits of this session on one aspect not yet placed under it go as one snapshot of their join (spec/commits.md §2; frontier over the session up to the last of their counters): they are then covered here and never go. A body the snapshot does not cover (behind an invalid one of its session) goes as it is, and with a snapshot among them all go as they are.
  - **Waiting**: while an own ephemeral upload under the label is unanswered on the connection, the node's later own ephemeral commits there wait (judged again once it is answered), so an aspect goes up as about one entry per round trip whatever the write rate.
  - Expiring writes are never coalesced (superseding thins them, below).
- **Holding**: every node holds the ephemeral commits it makes or receives, their blobs per label and their records, in memory only, never in its store or a bundle, until it restarts or they go (below).
  - **Verification**: a received one is verified as any commit (spec/commits.md §4) before its blob is kept, served or uploaded anywhere.
    - One whose author's record, a part's thing's record or a chain it needs is not held waits (pending, bounded per label by a share of the node's cap, below; the node keeps its blob apart, neither served nor uploaded).
    - Parts are judged (spec/permissions.md §5.2).
    - A session-form one applies atomically and an invalid part is un-merged (spec/crdt.md §4.6).
    - A part past its `expires` vanishes whole at every node (spec/crdt.md §4.7), so one arriving past it is never held.
    - An ephemeral commit more than `MAX_DRIFT` ahead of the corrected clock waits as a durable one does.
  - **Forgetting**: a node forgets an ephemeral commit whole, header included, once none of its parts is held any more (each covered, expired, superseded or its thing freed) and none waits, keeping of its header only what deleting its entries at hosts needs while it has any.
    - A freed thing's parts of a commit that also touches things not freed are dropped; the commit stays for those.
    - The record of a draft received from another node goes once no held or waiting ephemeral commit is on it and no held draft names it as owner (every commit about it carries the record again).
    - A copy of a forgotten commit arriving again applies and goes again by the same rules.
- **Compaction**: any writer of the aspect compacts (spec/commits.md §2, §5).
  - **Trigger**: a node writes an ephemeral snapshot of an aspect of a thing in a labeled closure here, or never under a label here, once the session-form bodies it holds of it without `expires`, two at least, cost more than twice a snapshot of it, each counted as its deltas' bytes plus a per-part and a per-entry charge (local policy, what a holder's cap and a host charge). A host's refusal triggers nothing.
  - **Dropping covered bodies**: every node drops a held body a held valid ephemeral snapshot covers (spec/commits.md §5) at once, keep bounds aside (ephemeral bodies have none).
    - Exception: a node drops a body it authored only under one of its own snapshots (local policy).
    - A snapshot stamped no later and covered by another goes the same way.
    - Of covered-equal snapshots the higher commit ID goes (§7).
  - **A snapshot turning invalid**: a node whose held valid snapshot turns invalid reconciles the label (§6) so the copies holders still have reach it again. If it may write the aspect and still holds a valid part of it, it writes a snapshot of the aspect from its state and uploads it (a new commit, which a host's delete tombstone on the old entries, §5, does not stop).
  - **Frontier**: a snapshot's frontier stops below a body of a session that is invalid or missing at the writer, so that session's later bodies are not covered until it is valid and held there.
  - **New sessions**: a node one of whose session-form writes under its current sessions turns invalid begins new sessions (spec/crdt.md §2.1) for what it writes from then on.
  - **Deleting at a host**: a writer deletes the entries of a dropped commit at a host (spec/crypto.md §7, level 3) once an entry of a snapshot covering it is held there, or names them as replaced (§5) in that snapshot's upload. One dropped for no coverer (expired, its things freed) goes at once.
  - **Superseded commits**: a node also drops a held plain ephemeral commit that has `expires` and whose parts carry no reset (spec/crdt.md §4.2; tombstones included) once each part is superseded by a valid held part of another plain ephemeral commit of its author on the same aspect.
    - The superseding commit and part qualify when all of these hold:
      - its `expires` is not earlier;
      - it carries no reset;
      - each of its writes has a later `ts` than every write of the superseded part and is not into a record it does not create;
      - its delta joined with the superseded part reads (spec/crdt.md §4.4) as it does alone.
    - This is judged when the superseding part is held valid (on arrival, at its build, or when it turns valid) and, on its remaining parts, when a part of the superseded commit vanishes at its expiry.
    - The dropped commit's writes then vanish as at its expiry (spec/crdt.md §4.7, ephemeral data) at every node, its author included, so a later removal or undo of the superseding write does not show them again.
    - Its author deletes its entries at a host once a superseder is held there, and no other node deletes them.
    - One superseded on arrival is not held.
    - An own write with `expires` superseded by a later own write before it was sent is never sent.
- **Caps**:
  - **At a node**: per label, a node holds at most a configured number of bytes of ephemeral bodies from others, each counted at an estimate of the memory it takes held (decoded, with the records beside it; local policy, at least its encoded size).
    - A commit is decoded only as far as a bound on that estimate made from its bytes (local policy) fits the room left under the cap, and applied only within it; others are not applied there.
    - Waiting commits take at most a share of the cap, counted at that bound.
    - An entry refused so is fetched again once the label's held or waiting bytes dropped below what they were at the refusal, one that can never fit (larger than the whole cap) not at all.
  - **At a host**: a host carries a label's ephemeral entries up to its cap (§5). An entry it refuses reaches no holder through it until room appears. The refused node uploads it there again later (local policy; room also appears without a log record, as entries expire).
- **Relay-only commits**:
  - **Dropped unopened**: a node drops a relay-only blob unopened when one of these holds:
    - it is larger than `MAX_RELAY_BLOB`;
    - its prefix expiry is passed or more than `2 × MAX_DRIFT` ahead of the corrected clock;
    - the node received that blob ID under that label before its expiry (remembered for at most a bounded number of blobs: past it the earliest-expiring is forgotten and its expiry becomes the label's floor, at or below which blobs are dropped).
  - **Delivery**: it verifies the rest like an ephemeral commit and delivers its valid signal parts to callbacks once. It holds and re-uploads nothing.
  - **Replay**: it remembers delivered relay-only commit IDs until their `ts` is `MAX_DRIFT` old, at most `MAX_DELIVERED` (past that the earliest delivered is forgotten and its `ts` becomes its author's floor unless lower, at or below which that author's relay-only commits are dropped), and drops relay-only commits whose `ts` is more than `MAX_DRIFT` from its corrected clock.
  - **Co-reader peer**: a co-reader peer serving the label passes a verified new one on, stamped as received: from a host to the sessions it serves, from a session to its other sessions and to the label's hosts it syncs with.

## 10. Transport and addresses
- Sync runs over any ordered, bidirectional byte stream with confidentiality and an authenticated peer key.
- A transport handshake has no deadline of its own beyond the transport's idle timeout; a host MAY close a connection whose peer sends no Hello (spec/wire.md §11.1) within a local policy bound.
- A host **address** is a transport URL plus the host's static public key; a client MUST check the host's key against it.
- **Keys and reach**: clients connect to hosts with an ephemeral transport key per connection. A node's dialable P2P key is separate from its signing key and published only in `reach.0`, together with its global addresses and its relays. Other addresses are never published; nodes that share data exchange them on a relayed connection (hole punching), or LAN discovery finds them.
- **`quic://host[:port]`** host addresses (port 4040 when absent, an IPv6 address in brackets):
  - QUIC v1 (RFC 9000, RFC 9001) with TLS 1.3 only, ALPN `osis`, 0-RTT MUST NOT be used.
  - Both sides MUST authenticate (client authentication is mandatory) with RFC 7250 raw public keys: an RFC 8410 Ed25519 SubjectPublicKeyInfo, signature scheme `ed25519` only, no certificates.
  - The host's key is the address key; a client's is fresh per connection, or a host's own address key when it dials another host.
  - SNI is ignored.
  - Each sync session (spec/wire.md §11.1) runs on a bidirectional stream the client opens; the dialer closes the connection.
- **Node keys**: a node's dialable key and its LAN transport keys are Ed25519 public keys (RFC 8032), each with a 32-byte seed as its transport secret. A node dials a co-reader's node with its dialable key as its transport key, and any other node (such as a link's sharer) with an ephemeral one. It proves itself a co-reader's node inside the session (open proof 3, §5), never by its transport key.
- **P2P transports**: a node dials a co-reader by dialable key over a P2P transport, each named by its own address scheme; only `peer://` is defined.
- **`peer://`** nodes are dialed by dialable or LAN transport key:
  - The URL is `peer://` then items separated by single spaces, each a socket address of the node (`ip:port`, an IPv6 address in brackets) or a relay, written `<key>@<socket address>` with the relay node's dialable key as 64 lowercase hex digits. Other items are skipped, and items past the 16th; none means LAN only. No address lookup service or default relay is used.
  - `reach.0` lists the node's dialable listener at each global socket address it is bound to, then its relays. An unspecified bound address stands for the local address of each route out (IPv4, IPv6) of a family the listener serves (an unspecified IPv6 address serves both) as of when it starts listening; global means none of unspecified, multicast, IPv4 broadcast, loopback, private (10/8, 172.16/12, 192.168/16), link-local, IPv4 shared (100.64/10) and IPv6 unique-local (fc00::/7).
  - Links and `label.0` list relays only.
  - A node listens on one UDP socket with QUIC as `quic://` (TLS 1.3, raw Ed25519 keys both ways, no 0-RTT, no session tickets), its key the dialable or LAN transport key, ALPN `osis` for sessions and, when it relays, `osis-relay`.
  - A dialer binds a fresh UDP socket per dial and address family its items use, and does each item's work from the socket of its family. It dials each socket address of the URL, and through each relay, at once; the first connection to complete serves the dial.
  - **Relay wire**: a client connects to the relay's socket address with ALPN `osis-relay`, pinning the relay's key, and makes each request on a bidirectional stream it opens. `addr` is 18 bytes: the 16-byte IPv6 address (IPv4 as IPv4-mapped) then the be16 port of the UDP source as the relay sees it.
    - **Register**: the client sends `0x01`; the key registered is its TLS key. The relay answers `0x00 ‖ addr` (the client's) and the key stays registered while the stream and connection stay open, a later registration of the key replacing it; or it answers `0x01` (refused) and finishes the stream.
    - **Dial**: the client sends `0x02 ‖ key (32)`. The relay opens a stream on the key's registration connection that starts with a 16-byte tag of the dialer's source, and answers `0x00 ‖ addr` (the dialer's); or, with no registration of the key it allows, answers `0x02`; or, when it cannot open that stream at once, answers `0x03` (busy). It never waits for room on a registration connection. After `0x02` or `0x03` it finishes the stream. A tag is the same for every dial from one source through that relay, differs between sources, and reveals nothing of the address to one without the relay's secret; the target counts it as the connection's source. The relay never sends a side the other's address.
    - From then on the relay forwards each side's bytes, and its finish, to the other unchanged. A stream starting with any other byte is dropped.
  - **Relayed connection**: TLS 1.3 runs over the forwarded bytes as on a direct connection (the dialer is the client and pins the target's key, ALPN `osis`, raw keys, no session tickets, no early data), records exactly as RFC 8446 frames them. The plaintext starts with an `addr` from each side, which each sends before reading the other's: its own address as the relay saw it (the dialer's from its Dial answer, the target's from its Register answer) when it consents to the peer's TLS key (IP consent), else 18 zero bytes. Then the plaintext is one session; a relayed connection carries no other. Its end is the TLS close_notify; forwarded bytes ending without one end it abnormally.
  - **Registration streams**: a registering client lets the relay open 2048 streams at once on the registration connection, with a connection receive window at least 2048 times its stream receive window, so forwarded streams it has not read never hold back another. It holds at most 1024 forwarded streams not yet serving an accepted connection (handshaking or queued), ending the oldest past that.
  - **Hole punching**: when both sides of a relayed connection sent a nonzero `addr`, the target sends a QUIC Initial from its listening socket to the dialer's address (a handshake it never completes), and the dialer dials the target's address from the socket it reached the relay from, as a direct connection; otherwise neither does.
  - **IP consent**: a node gives its IP address only to the nodes it shares data with: on a relayed connection it sends its `addr` only when the peer's authenticated TLS key is the dialable key of such a node, its `reach.0` goes only under labels it syncs (spec/permissions.md §4), and it dials only the socket addresses such a node gave (`reach.0`, a LAN announcement) or a link it follows lists. Limits: what a link lists, relays included, is its maker's choice, so following it shows the node's address to whoever made it; an address in `reach.0` stays readable under each label it went under, so a reader added later learns the address the node had then (a rotation renews keys, not addresses).
  - **Switching**: when a direct connection completes after a dialer began using a relayed one, it closes the relayed one and its next dial of that key uses the direct one.
  - **Relaying** is a node's choice. A relay accepts registrations only of the keys it allows, and bounds per source (an IPv4 address, an IPv6 /64) the bytes per second it forwards and its share of relay connections. It sees addresses, volume and the keys dialed, never the data.
  - A `peer://` entry in a label's `hosts` is never dialed as a host: a label with no other entry has no host, and its nodes serve it.
- **LAN discovery** announces nothing stable across networks or meaningful to strangers: a tag and a transport key fresh per network join, never the dialable key.
  - **Tag**: `kdf("lan tag", lan secret, le64(window))` (first 16 bytes), with window = `floor(unix ms / 600000)`. The 32-byte random lan secret is in `reach.0`. A co-reader matches tags of the nodes it knows for the current and adjacent windows.
  - **Joining**: a node joins anew (a fresh transport key and listener, announced at once) whenever its network may have changed.
  - **Announcement** (provisional): a UDP datagram to port 47380 on each address family the node has, as an IPv4 broadcast (255.255.255.255) and an IPv6 multicast to the link-local all-nodes group ff02::1 on each up interface with a link-local address, of exactly 124 bytes:

    | offset | size | field |
    |---|---|---|
    | 0 | 10 | `"osis lan 1"` (ASCII) |
    | 10 | 16 | tag |
    | 26 | 32 | transport key |
    | 58 | 2 | listening port, big-endian: the listener's port on the datagram's family |
    | 60 | 64 | sealed signature |

  - **Sealed signature**: the Ed25519 signature under the node's dialable key over domain `"osis v1 lan announce"` and digest BLAKE3(tag (16) || transport key (32) || be16(listening port)) (spec/crypto.md §2), XORed with the first 64 bytes of the XOF form of `kdf("lan sig", lan secret, le64(window) || digest)`, window as for the tag and digest the 32 bytes above.
  - **A receiver ignores**:
    - any other datagram;
    - one from a source address that cannot be on its LAN (only IPv4 loopback 127/8, private 10/8, 172.16/12, 192.168/16 and link-local 169.254/16, and IPv6 loopback, unique-local fc00::/7 and link-local fe80::/10 count; shared address space 100.64/10 does not);
    - one whose signature does not open and verify under the lan secret and dialable key of the node whose tag matched;
    - an announcement from any source address other than the first it verified that announcement from;
    - one of an earlier window than the newest it verified from that node (replays).
  - **Dialing**: it dials the announced key at the datagram's source address (an IPv6 link-local one on the interface it arrived on) and the announced port. The address is a route to the node only once a connection through it is up (the transport authenticated the announced key).
- **Client port** (spec/wire.md §11.2 kinds 24-29) is served only on a node's own listeners (its dialable key, LAN keys, its unix socket, its client listeners), never on a host address.
- **Client listener**: a listener at a URL the node's owner chose, with a transport key of its own.
  - That key is an Ed25519 key from a 32-byte random seed, derived from nothing else and independent of the node's signing, dialable and LAN keys, published nowhere but in the addresses handed to its clients, changed only by hand.
  - Its `Hello` static key is that key, and it serves only kinds 24-29 and Ping (any other: Error 11).
  - A node SHOULD keep connections and sessions that have not authenticated apart from every other listener's, within a bound of its own, the oldest giving way to a newcomer from another source.
- **`unix:///path`**: a path socket (never an abstract one), no TLS.
  - Each side reads the other's uid from the kernel (`SO_PEERCRED`) and accepts only its own uid.
  - A side's key for the address is BLAKE3(`"osis v1 unix peer"` ‖ be32(uid)).
  - Only a local client dials one; a node never dials a `unix://` address taken from synced data.
  - A session on it is a **main session**, acting as the node's main actor (Auth without secret); a session on any other transport never is, whatever key it presents.
- **Client-actor session**: a session on a keyed transport, whose dialer pinned the node's key, that sent a current bearer secret in Auth (spec/wire.md §11.2).
  - The node acts as its client actor: it signs the session's commits as their author with that actor in the header's actor field, and holds them to that actor's rights itself, since receivers judge only the author node's (spec/permissions.md §5).
  - A client's secret is never sent on another transport.
  - A client whose connection ended dials again with its session id unchanged, sends Auth, and resends each write that had no answer, marking it (spec/wire.md §11.2). A node that no longer remembers it answers that its outcome is unknown.
- **Group source**: a node MAY read and write a group through another node it is a client of (the group's source).
  - A thing in a group sourced at another node goes there, whatever else holds it; the copy this node holds never answers.
  - A write on it is refused while a group carrying it (§3) syncs here or is sourced at another node.

## 11. File bundles
A bundle is a one-way log replay for a set of labels: registration paths, entries with wraps and stamps, blobs, deletions (spec/wire.md §12). An importer treats it as a peer with no cursor.
