# Sync
> Summary: How nodes and hosts store and exchange blobs: labels, what goes under them, host operations and their authorization, the sync protocol and convergence rules, ephemeral commits, transports and bundles.

## 1. Blobs
- A **blob** is one of:
  - an encrypted commit (header plus unpurged deltas; spec/commits.md);
  - an encrypted chunk, tree node or page (spec/data-model.md §6, spec/crdt.md §8, a header list spec/commits.md §1);
  - an inbox blob (§3).
- Hosts cannot tell them apart except as §4 states.
- **Layout**: **clear prefix** || ciphertext. The prefix holds a salt, an optional expiry `T`, the blob's **class** and the delete-key commitments, one per level (spec/crypto.md §7). Ciphertext: spec/crypto.md §5. Bytes, padding, **Blob ID** and the `MAX_BLOB` bound: spec/wire.md §5.
- An add event or fetch answer whose bytes do not hash to its blob ID is ignored, whoever sends it.
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
- A synced thing has a **label**: the unit a host stores. A label has an **index** i (0 for a group's first label) and the role keys below.
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
- **Claim set** of a step: padded with random keys to a power of two, in random order. It lists each **reader** M of the registered read epoch: every actor holding its read secret as the registrar knows it at registration (the holders of boxes carrying it, the first admin included while its record edge stands; a holder re-sealed later opens by sync key).
  - A reader is listed by its claim public key (derivation: spec/wire.md §8). M's X25519 key is the X25519 half of its read-role KEM key in the newest `keys.0` of M the registrar holds (a key actor: its single KEM key; an account: its newest open epoch's, spec/crypto.md §3). A non-contributory DH result omits M.
  - A reader that is a key actor other than a node or an account (a link key) is listed instead by its **static entry** (spec/wire.md §8), the same 32 bytes.
  - The registrar erases the step private key after signing.
  - M derives its claim key from its own private key and the step key; it tries each keyset epoch it has held.
- **Entry boxes** of a step: one for each reader that is a key actor other than a node or an account (a link key), sealed to its KEM key (spec/crypto.md §4 sealed form; AD = (label ID, step key)). Layout: spec/wire.md §7.
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
- **One sync ID per actor**: a commit that gives a thing role secrets of its own (spec/permissions.md §3) MUST also create its label (index 0, unless it already has one) and record it in `label.0`, in that one commit. That label is the thing's **home label**.
  - Its hosts are the ones named by the operation making it, else those of the nearest thing up its record chain with a live label, else none.
  - So every holder of a role on a thing with secrets of its own can read it through that label, whatever else holds the thing. It stays for the thing's life; holders are removed, the label is not retired.
  - A plain thing has none. A thing in no labeled group is not synced; a plain thing in a synced group syncs under the group's label.
  - The home closure holds the actor thing and what its `group.0` lists, nothing by record chain.
  - The nearest actor with a home label up a labeled group's record chain carries that group's `label.0` and `created.0` writes, while the record edges between them stand at the writer (§3).
  - A link's K label is K's home label.
- **Inbox**: an actor with role secrets names its home label in `keys.0` as its inbox for inbox blobs (§3), with the deposit seed, in the commit that gives it the label.
  - A sender uses the inbox the actor's `keys.0` names; a sender holding none cannot reach it.
  - An account's inbox is its D's home label (spec/permissions.md §1). Other key actors have none: a node receives its grant on D only over a direct connection to a node of the account (pairing); a link key holds its label from its link and claims the current step by its static entry (§5).

## 3. What goes under a label
- **Closure**: the blobs of group G are the commits touching any thing in G's transitive closure (through `group.0`, spec/data-model.md §8), plus the chunk, tree-node and page blobs they reference (every blob their values link, whether or not the linking commit's chunk list names it).
  - Each node tags commits with their things' `groups.0` and retags when group membership changes.
- **Entitlement**: a thing's **reader actor** is the thing if it has secrets of its own, else the nearest actor up its record chain that has them (a key actor is its own). G's actor is the group thing if it has secrets of its own, else its base actor (spec/crypto.md §3). G's actor may read a thing iff the thing's secrets derive from its own or it holds read or above on the thing's reader actor. A commit's blob belongs under G's label iff G's actor may read a part of it on a thing of the closure (or published there, §2).
  - Only a writer of G stamps entries (§5).
  - A node that is not one deposits what it must place there (its account's chain certificates, rotations and thing lists, its invite grant or self-removal, its listings, its history adds (spec/permissions.md §3), and the revokes it must place by spec/permissions.md §4) and relays or deposits the must-hold entries it holds (§6).
- **One blob per commit**: a commit is uploaded as one blob holding every part of it the uploader holds and can seal, each part in the section of its thing under the thing's read secret (spec/wire.md §4; a part of a thing whose read secret the uploader lacks, a key actor's own record or card, travels as a certificate copy). Every label of every thing the commit touches carries the one blob under its label's wrap; hosts and nodes syncing several of those labels dedup it by blob ID. No size split: a commit stays within `MAX_BLOB` by paging its deltas (spec/crdt.md §8), largest first, or is refused at the writer.
  - A node judges a blob by the parts the label's actor may read (§6); a section it cannot open it copies verbatim when it encrypts the commit again (a tombstoned entry, a purge rewrite).
  - A section opens with the thing's read secret at the epoch the writer used: a reader of the thing holds it (its own, through its history boxes; a plain thing's by derivation through the record chain the section lists from a member it holds epochs of), and a holder of a role on the thing's reader actor keeps up with its rotations through that actor's label (§2).
  - **Per-label copies**: besides certificate copies (below), a label whose readers could not open a part's section in the shared blob gets a fresh blob of the parts its actor may read, one section under the read secret of the label's group, never shared with another label; judged like any body of the commit. Exactly two cases: a role commit with such a part on a thing other than the label's actor (its boxes are what give the readers that thing's secrets: a rotation, a grant, a cross-published `label.0`, §2); a part on a thing whose read secret derives from neither the label's actor nor an actor in its closure (a cross-published `created.0`, §2; a thing added from another actor's tree, read by role on a reader actor whose rotations the label does not carry). A blob a node opens only under the label group's secret for a section on another thing is such a copy: its sections are not copied into another encryption.
- **Retag**: when a thing joins a group, any writer of the label that holds the thing's live blobs adds them under it; when it leaves, delete-key holders delete them under the old label as they see the change (§7).
- **Certificate blobs**: chain certificates, accounts' rotations and ended things' mintings (header-only copies), list blobs, record blobs and revokes (spec/permissions.md §4, §5.5): copies of the parts of a role commit about one actor, thing lists, or raw creation records (spec/wire.md §3).
  - They go under a label as a fresh encryption per label, never as a blob shared with another label.
  - The chunk and tree-node blobs of a linked frontier or header list go under it too, as the same blobs (a link names them) with a filler wrap.
  - A writer promoting a deposited commit completes its author's chain under the label from what it holds (§5).
- **List blobs**: a blob carrying thing lists of one rotation (spec/permissions.md §5.5; bytes spec/wire.md §4, List tree), wrapped per label like a commit, with no expiry and no commitments, fetched first (order 0). Under a label it carries only thing lists of things in the label's closure or touched by a commit placed there as a certificate. A node holds a list blob's thing lists once it holds its rotation; one opened beside the rotation (in one batch) is held as the rotation applies. A non-writer deposits it; a writer promotes it once each thing list in it verifies against the root of a rotation it holds.
- **Inbox blob** (spec/crypto.md §5; layout and payload spec/wire.md §9): the parts about actor G of a role commit, boxed to G, with the label IDs and host addresses of those things it names that have labels of their own.
  - **What it carries about G**, any of:
    - a grant with G's boxes;
    - a change or removal of G's grant;
    - a re-seal of G;
    - a rotation boxing G where G held no box at the read epoch before it.
  - **Placement**: under G's inbox (§2) by deposit, or by upload when the sender holds the inbox label's write key. The inbox group's admins may delete it earlier than its expiry.
  - **Re-send**: its prefix expiry is `INBOX_LIFETIME`, after which the sender re-sends, and sooner once the label it went under is no longer the recipient's inbox (`keys.0`), unless the recipient has since acted on it: a commit by it writing a thing the blob names or a thing whose record chain (spec/permissions.md §1) reaches such a thing. Acting elsewhere does not count. A sender MAY bound the number of re-sends.
  - **Stamping in place**: a writer of the inbox's group stamps a deposited inbox blob in place (§5).
    - It does so when either:
      - its commit is applied, valid in every part the blob carries, and about an actor whose inbox the label is (it has parts a copy below would take for that actor); or
      - its user declined it (below).
    - It does not when another blob of that commit under the label is stamped, or the blob's prefix expiry is more than `INBOX_LIFETIME + 2 × MAX_DRIFT` ahead of its wall clock.
    - A blob so stamped leaves the deposit budget and stays readable until it expires.
    - Every other inbox blob stays deposited, until it expires or is cleared (§5).
  - **Following a payload label**: the payload's labels and hosts are the sender's word. A recipient follows (opens, dials the hosts of) a payload label only:
    - while the blob is unexpired and its commit is applied, or held unjudged, and not judged invalid;
    - for a thing it knows no label of, whose read secret the commit gave it (a `secrets.0` delta valid, or a box of it that opens while the commit is unjudged or pending);
    - for a label no `label.0` it has applied records;
    - at most one per blob.
- **Label hints**: the label an inbox blob names is its sender's word until a `label.0` the node holds records it.
  - Blobs naming one label under different things are tried in turn: under the first thing not failed since the label's last retry, at the hosts all of them name, each retried after `resync_ms`.
  - A hinted open by a sync key holds only at a head of that key, whatever the host answers.
  - What a connection delivers under a label is read under the thing the label is opened under on that connection; elsewhere a label belongs to the group whose held `label.0` records it.
- **Invite requests**: a recipient node applies the commit of an opened inbox blob, and follows what it names, only once it **admits** the blob.
  - It admits the blob when either:
    - the commit is already held (applied, or an entry of it held; a sibling node that accepted it places its copy under the home label); or
    - its sender is **connected**: the header's author is a key actor whose creation record the node holds and under whose key (an account's: at the epoch it names, with that epoch's chain held) the commit's signature verifies, and the author has an effective role now (spec/permissions.md §1, as this node judges it) on a group the node syncs (§2), on a thing up such a group's record chain, or on an account whose contact card the node imported.
  - A blob not admitted is an invite request: its commit is not applied, its chain certificates (spec/wire.md §9) are not ingested, and nothing it names is fetched, followed or dialed until the user accepts it.
  - It is judged again as the node's state changes.
  - Accepting admits it.
  - Declining one leaves its commit unapplied, at that node and for good, from every inbox blob carrying it. The same commit arriving in a blob under a label the node syncs (a sibling node that accepted it placed its copy under home) is applied as any commit: the acceptance wins.
- **Grant copy**: a grantee node that accepts a grant for an actor (from the inbox, from K's label, or by pairing) places a certificate copy of the grant, with the `label.0` commits of the labels it reached and those things' records (a record blob, spec/wire.md §3), under that actor's home label; not when an entry there already holds the grant's parts, counted as for chain certificates (spec/permissions.md §4).
  - From an inbox blob only a node with admin on the actor copies, and only, of a valid applied role commit:
    - the carried parts on the things where a `roles.0` delta writes the grant of the actor or a `secrets.0` delta boxes it;
    - with the `created.0` commit and every `label.0` commit of those things that the payload names (no `label.0` commit of a thing the actor reads no more);
    - and the author's chain of each (spec/permissions.md §4), that chain without any `keys.0` but its author's own;
    - and nothing from a blob whose expiry is less than `INBOX_LIFETIME` / 2 away.
  - Nothing else an inbox blob carries is placed.
  - A node runs this whenever it opens an inbox blob, its commit held or not.
- **Inbox blob order**: a sender still opening or registering a label an inbox blob names at a host it is connected to, open at none of them, deposits the blob after that ends. A node told a label is unknown at a host, with no step of it to register, opens it again after a back-off of `retry_ms` doubling per refusal up to `resync_ms` (local policy).
- **Contact card**: a link (spec/permissions.md §7) with read role to an account's profile thing P, a group of itself with no items: its label carries P's own aspects, the account's record (a record blob) and, as certificate copies, its `keys.0` commits and rotations (spec/permissions.md §5.5).
- **Unjudged blobs**: a receiver keeps blobs a peer placed under a label even if its own closure disagrees, while it cannot judge them: a commit it holds pending (not parked) or an entry of the label it can open and has not applied, an entry awaiting a record included, within its bounds on unjudged input (spec/commits.md §4 Pending storage); then §6 decides.

## 4. Host state
Per label:
- **Registration path**: the steps from the genesis step to its **head**: every step's role keys, step key, `prev` and signature; each step's claim set and entry boxes until it has been superseded for `ROLE_KEEP`, longer by policy.
- **Entries**: blob ID; wrap or, for chunk/tree/page and inbox blobs, a random filler; stamp or none; deposited flag; optional pending deletion time.
- **Tombstones** (blob ID) of deleted entries, kept `TOMBSTONE_LIFETIME`.
- **Log**: an append-only log of events (entries added, deletions, registrations) with sequence numbers, trimmed up to the position of every durable entry removed (deleted or expired) `TOMBSTONE_LIFETIME` ago, and further at the host's choice (a cursor below the trim gets Error 15, §6).

Across labels:
- Blob bytes are stored once per host and deleted when no label references them.
- A label the host syncs itself (it reads the group, §2) is held as the node holds it: its path is the one the node serves from the steps its `label.0` records (§10), its entries those the node holds with their bytes, each blob once for the node and the host. Admission, caps and rates (spec/data-model.md §9) govern only the labels it does not read; an entry of a label it reads leaves at its expiry by the node's judgment (§6), not the host's.
- Ephemeral entries, their log events and their tombstones are held in memory only and lost at a restart. No sequence number handed out before a restart is handed out again.
- Relay-only blobs are never held.

## 5. Operations and authorization
Each operation names a label. Writes are signed with the role keys of the host's head; reads need the label opened on the connection:
- **Open** (sync key or claim key): a signature under `"osis v1 label open"` over (label ID, the host's connection challenge from the handshake, its static key). Opens the label on that connection for download, specific-blob fetch, reconciliation and subscription.
  - A sync key is matched against the head first, then against the superseded step on the path the open names, if it bears that key, else (naming none) against the newest superseded step on the path bearing it. A step without a rotation shares its parent's keys, so a client holding a step names it: only that step's child verifies under it.
  - A signature under a superseded step's sync key is answered with that step's child on the path (without its claim set) and nothing else. The client verifies it under the step's delete key before using it. An open naming a step off the path, or one not bearing the key, is refused like an unknown key.
  - An open holds under the sync key of the head it was made at (by a claim or static entry too). Once the head is a step with another sync key, the host ends it on that connection with the label's subscription (the last push carries that head's event, §8) and answers its reads 8 until the label is opened again.
  - An open by a connection's shared set (Proof 3, §10) is not tied to steps: it holds while the shared set holds it.
  - A client whose open head gains a child with another sync key (its own registration included) opens again.
- **Claim**: an open signature under a key V, with (step ID j, V).
  - If V is in step j's claim set: j the head opens the label, j on the path is answered with its child as above. Otherwise refused like an unknown key.
  - A key actor other than a node or an account sends its signing public key with the open signature instead of (j, V), only to labels of things it holds a role on or that it follows for itself (its link's label). The host opens the label if its static entry is in the head's set, and that key reads the current read secret from the head's entry box.
  - A holder that missed n steps walks them in n round trips, verifying each step under its parent's delete key (the genesis step against the label ID), then downloads the rotations and derives the current keys. The claim is bootstrap only.
  - A claim at a step whose set the host has dropped is refused; such a holder is stranded (spec/permissions.md §4) and is reached only by re-seal (spec/permissions.md §3).
- **Register** (delete key of the parent). Relayable by any node.
  - Accept a genesis step only if its delete key hashes to the label ID and the label is new. A host that syncs the label takes no genesis step by Register (refused for now, code 4): its path comes from `label.0` (§4).
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
  - Anyone holding a stamped entry may relay it, hosts included (replication between hosts is push only: download needs an open). A stamp under a superseded write key is refused (code 9): such an entry goes as a deposit (Deposit).
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
  - Refused like an upload, when the label's deposit budget is full, or for a relay-only blob (code 1). An ephemeral deposit is held as an ephemeral entry (§4), counting toward the label's ephemeral cap and the deposit budget alike.
  - **Budget**: host policy, with a recommended minimum (spec/wire.md §2), one per label for durable and ephemeral deposits. An entry leaves the budget when stamped, deleted or expired, or with the host's restart for an ephemeral one. The reply reports the remaining budget only to a deposit whose signature verifies under the head's deposit key.
  - A deposit whose signature does not verify (code 1, or 9 under an earlier deposit key) and one under an unknown label learn the code alone, neither budget nor head.
  - **Sending**: a client sends a deposit of its own write (sealed, wrapped and signed when made) to each host of the label until that host answers it, also after losing read access to the label's actor (spec/permissions.md §3); an inbox blob for an inbox listing no host goes as a Deposit item to a node of the inbox instead (§10 Shared set). A reader's deposit of a body it holds (§6) is no write of its own: each pass at the host sends it again while the host lacks it.
  - **Refused for now** (unknown label, rate limited, budget full, storage cap, an Error reply) is no answer: the deposit is sent again after a back-off (local policy, bounded; a deposit the host takes ends the back-off of the client's others at that host and label) until the host takes it or it is moot.
  - **Refused as signed by an earlier deposit key**: signed again with the current one, or dropped when the client holds no other.
  - **Moot**: an inbox blob once its delivery is forgotten or sealed again (§3), any deposit under a label the client sees replaced.
  - **Promotion**: a writer that verifies a deposited commit the label must hold re-uploads it stamped (promotes it), only once its author's chain for the deposited deltas (spec/permissions.md §4) is under the label.
    - A promoter completes the chain it holds, placing the missing deltas as its own certificate copies with the promotion.
    - A record blob counts toward the chain only stamped or the promoter's own; a deposited record blob is never promoted (it waits for clearing).
    - A writer that holds neither the commit applied nor the chain leaves the deposit unpromoted.
    - The author's chain under a label leaves out every `keys.0` but the author's own.
    - A certificate copy is never deleted for an incomplete chain.
- **Clearing deposits**: a node holding the delete key of a label keeps at most `DEPOSITS_WAITING` entries and `DEPOSITS_WAITING_BYTES` bytes per host of the deposits there it can do nothing with.
  - Those are every deposited entry whose bytes it has received except:
    - one it opened as a commit it judges valid (as a reader judges what it deposits, §6);
    - an inbox blob it would stamp (§3);
    - an inbox blob whose commit is not applied and whose prefix expiry is within `INBOX_LIFETIME + 2 × MAX_DRIFT`.
  - Each counts at its blob's size, whether or not the node still holds its bytes.
  - Past either bound it deletes them at each pass, in this order:
    1. all but opened invite requests (§3) with a prefix expiry within that bound, those with no expiry or a later one before the rest, then earliest to expire first;
    2. then those requests, earliest to expire first.
- **Placed**: a commit a node made, or a self-removal by its account, itself or a key actor it holds (spec/permissions.md §2) that it holds, is placed when each label it syncs of the things the commit touches holds the parts of it the label's actor reads that it must hold (§6) in an entry held at a source, or covered by a snapshot there. An entry is held at a source when it is present at one of the label's hosts, not counting as lacking there (above), or when a co-reader it served the label to on a connection whose proofs identify a known account other than its own (an own node never counts: it leaves by the same commit) (§10) reported a position (§10 Lost; on that connection, also from a message carrying the label's events after the label left the shared set) at or past the position where the node's log first held the entry (for a member being ended, the entry first logged at or below its `until`). Under a label with a host such a report counts only from an admin of the actor the label's keys derive from, and only for a commit writing that actor's `roles.0` (Re-registration uploads it to the hosts); under a label with no host, from any such co-reader. A node records each such report on a commit not yet placed in the step that took it, kept while the entry is. Copies of it elsewhere (certificate copies, inbox blobs) do not wait for it (spec/commits.md §4). A reader can pull a node's labels while it publishes `reach.0` or a connection shares a sync ID (§10).
- **Delete**: by the delete key, or of one entry by delete keys of levels: one delete signature per commitment group of the blob's prefix, each verifying under that group's commitment at its level (spec/crypto.md §7; one signature may cover several groups committing to the same key), plus a signature under the head's write key when any level is 3 (thing write secret), else its sync key; any other is refused. An empty group (a `nobody` delta's, or a header list's of a commit listing no level-2 key) is never covered: such a blob goes by the delete key, at its expiry, or by Replace.
  - Removal leaves a tombstone for `TOMBSTONE_LIFETIME`.
- **Expiry**: at the prefix's `T` the host deletes the entry outright: no tombstone.
- **Download**, specific-blob fetch, reconciliation (§6) and subscription (§8): only for labels opened on the connection; a blob is fetched by ID only as an entry of an opened label.
- **Host caps**: hosts cap storage per label and the memory of ephemeral entries per label (and in total), counting each entry's, log record's and tombstone's overhead besides its blob.
  - An ephemeral upload past its cap is refused (code 12).
  - At the total cap the label using most gives way: its oldest log records, then its oldest entries, deleted with a log record and no tombstone.
  - An ephemeral entry's tombstone lasts `MAX_DRIFT` (in memory).
  - Hosts may rate-limit deletes, deposits, registrations (code 4) and relay-only uploads per label.
  - A cursor below a trimmed ephemeral log gets the live ephemeral entries added since in place of their add events.
- **Co-reader peer**: between readers a node serves its connection's shared set by the Stream (§10) alone; a peer opens nothing there and uploads nothing.
  - While a reader can pull it (§5 Placed), a node places in its own store what each label it syncs must hold of its own (the must-hold bodies it would upload, its certificates), whatever hosts are connected; a pass at a host uploads what that host lacks of it. Of the entries in its store no host holds or is being sent, it drops what its sync would delete at a host (a body with live writes only once a carrier is under the label) or what expired.
  - A co-reader peer that syncs a label with no host serves it as its own host, while a reader can pull it (§5 Placed):
    - it issues a child step when it would re-register at a host (recorded in `label.0`);
    - it holds the bodies it holds that the label must hold (§6) and the blobs they link, its certificates, and the inbox blobs it sends to an inbox label it syncs with no host;
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
  - Every node uses its own wall clock wherever wall time is used; nothing another node sends changes it.
  - A node SHOULD estimate a dialed peer's clock offset from its handshake and Ping/Pong round trips (spec/wire.md §11; round-trip corrected, robust to an outlier, ignoring samples whose round trip exceeds a few seconds) and report an offset of more than a few seconds as a diagnostic.
- **Flow control**:
  - **Requester**: either side of a connection, whoever dialed, keeps at most `WINDOW` in flight on it, counting per request it sent and that is not answered (the Stream's and the shared set's included) its frame length plus a reply allowance:
    - `MAX_MESSAGE` for Reconcile;
    - its `max_reply` for a Sync, Fetch, Pull, Call or Sub (spec/wire.md §11.2);
    - `SMALL_REPLY` for every other kind.
    - It sends the next request while below `WINDOW` (so one always goes), in the order it made them.
  - **Pushes**: a peer sends a push (§8) only while its bytes not yet taken by the transport on that connection, the push included, stay within `REPLY_BUDGET`, or none are. Otherwise the subscription's pushes wait (Notifies likewise), continuing from its position once they fit (held subscriptions in turn, so none starves another), and a relay-only entry that does not fit is not pushed on that connection.
  - **Closing**: a peer MUST NOT close a connection over unwritten bytes below `WINDOW + 2 × (MAX_MESSAGE + 4)` plus its own bytes in flight there (Requester), and MAY close one beyond it.
  - **Stall**: a requester SHOULD close a connection, whichever side dialed, on which its oldest request sent and not answered has not moved for minutes, and redial. It moves by its own events: when it is sent with no other outstanding, when the request before it is answered, when bytes of a reply to it arrive (a frame not yet complete included), and when the transport takes bytes this side wrote up to the end of its frame. A reply to any other request moves nothing. Any other bytes received (pushes, the peer's own requests) move it only while no more than `WINDOW + 2 × (MAX_MESSAGE + 4)` (Closing) plus `WINDOW + 2 × MAX_MESSAGE + 4` (Unanswered requests) of them arrived since it last moved by its own events.
  - **Unanswered requests**: count the frame lengths plus allowances of the requests a peer receives before it has answered any of them. A peer MAY close a connection whose count passes `WINDOW + 2 × MAX_MESSAGE + 4` before it answers them, without running the request that passes it.
- Between two readers of a label the Stream (§10) replaces cursor sync, first sync and range reconciliation below.
- **Cursor sync**: a client keeps a cursor per (peer, label) and sends: the cursor, its own new blobs inline, and the blob IDs it gained under that label from other sources since. The peer replies with its log after the cursor minus those IDs, blobs inline, and a want-list of the gained IDs it lacks, which the client then sends.
- **First sync** of a label at a peer, from no cursor:
  - The node lists it (Sync with `inline_limit` 0, to its end) and then fetches every listed entry it lacks, in the order of the wraps (spec/crypto.md §5):
    1. order 0;
    2. then what does not open that the peer holds deposited (no stamp, §5);
    3. then the highest order first;
    4. last the rest of what does not open, ranked again as secrets arrive.
  - Order 0 goes before anything else is asked. How many are asked at a time is local policy.
  - A body not fetched yet is one not received (spec/commits.md §4).
  - A node runs passes once order 0 is here, or once a fetch of it from the host counts as asked no longer (§10, Bodies).
  - An entry that opens and is not here keeps what it would settle unsettled, as an unopened entry does, except that the node's own commits count as established uncovered (no snapshot covers what only it has sent), so it sends its own writes; it runs no repair (§7).
  - The pass ends, and the cursor stands at the listing's end, when nothing is left to fetch. A node that stopped part way (a restart, a lost connection) goes on from what it listed, without listing again.
- **Range reconciliation** (fallback when a cursor is missing or invalid, or the gained list exceeds a message): range-based set reconciliation over the IDs of the live entries (additive fingerprints, 16-way splits; spec/wire.md §11.3).
  - After a cursor the peer's log was trimmed past (Error 15), an entry the client knew present there that the peer lacks was deleted there, as by a deletion event.
  - After any other fallback it is only not present there.
- One connection may sync many labels; a blob under several of them SHOULD cross it once (spec/wire.md §11).
- **Convergence**: a label's **required set** is its closure blobs (§3) plus what is placed there from outside the closure:
  - the certificate blobs of spec/permissions.md §4, judged by the deltas a blob holds, whatever else its commit writes, a list blob by its thing lists, a record blob by its records (never must-not-hold: no delete key covers it); an ended thing's certificates outside the closure by its dependents (spec/commits.md §5 Ending);
  - the grantee's certificate copies and cross-published `label.0` commits (§3);
  - unexpired inbox blobs.

  Per node, a body it holds is **must-hold**, **must-not-hold** or **may-hold** at a label. A body meeting a must-not-hold condition is must-not-hold whatever else holds of it.
  - A delta is **kept** while it is before its keep-at-least bound (in history by the settings the node holds, spec/commits.md §5 The setting). One out of history is neither must-hold nor fetched; a node that dropped it fetches it none when a later setting puts it back in history.
  - **must-hold**: in the required set and, for a closure body, one of:
    - a delta of it kept, whatever snapshot covers it;
    - established uncovered: the node can join it and no held snapshot of the aspect under the label covers it (spec/commits.md §5); a signal's delta is never joined, so it is must-hold only while kept.
  - **Header-only blob**: in the required set only as the lasting header of a commit lasting on a thing of the closure whose actor the label's reads (spec/commits.md §5), with no other body of the commit wanted there, and then is must-hold, whatever snapshot covers it. One of a commit with a permanent delta or a purge request that is not lasting here is may-hold: another node may judge it lasting.
  - **must-not-hold**, any of:
    - purged;
    - expired (its blob's prefix expiry, §3, whatever of it the label's actor reads);
    - outside the required set;
    - a blob of commit C whose delta set is a strict subset of another held blob of C under that label that is not itself must-not-hold and whose extra deltas include one only a blob carries: kept or holding a live write, and covered by no snapshot under the label;
    - under D's home label (target, issues/account-signing.md step 7), another node's card commit (spec/permissions.md §4) once a later valid card commit of that node writing the same aspect is under the label (an entry of it this node opened and checked against its header);
    - under D's home label, another node's card commit, for `node.0` and `reach.0`, once that node is a node of the account no more after an applied edge write on D ended its grant (removed it, or its `until` passed).
  - **may-hold**: the rest: covered, out of history, parked, unfetched pages, a certificate blob whose author has no other blob under the label.

  After syncing:
  - **Writer**: uploads every must-hold body the label lacks, as a fresh encryption if the old blob ID is tombstoned or its entry counts as lacking there (§5). A blob of the commit that is not must-not-hold and holds every delta of the body that no snapshot under the label covers holds it.
  - **Reader**: sends each must-hold entry it holds that the label lacks: relayed under its stamp when the head's write key verifies it, else deposited while it judges the body valid (any author's, judged by its author's rights when promoted, §5).
  - **Neither** uploads nor relays a body a delete removed from the label (an entry of it that is not a certificate copy, within `TOMBSTONE_LIFETIME`) while both of these hold:
    - each of its deltas only a blob carries (as for a strict subset above) is held there by another blob of the commit that is not must-not-hold;
    - no held purge request signed by ones that could hold the right (spec/commits.md §4) names a delta of it without dropping it (spec/permissions.md §6).
    - So once a delete or a bad Replace took a delta covered by a snapshot under the label, no one places it again, even a node that judges it replaced later (holding other bodies, spec/commits.md §5) and still keeps it: the host keeps the snapshot's live state, not that delta's history before its keep-at-least bound. Once no valid snapshot under the label covers it, its holders place it again.
  - **Delete-key holders** delete must-not-hold bodies.
  - **Dropped bodies**: a node that dropped a body keeps knowing its entries (not its key or wrap) and each one's prefix salt once it had the blob (a delete-key signature's, spec/crypto.md §7), never its bytes: the bytes of a chunk, tree node or page of a dropped delta, whoever brings them, are read for the salt and not stored. A delete-key holder lacking a salt fetches the blob for it. When the body counts as never received again (spec/permissions.md §5.2, §6) it fetches them again where present, and otherwise takes the body from a holder's upload (it is must-hold there: no valid snapshot covers it).
  - A blob holding a delta the node dropped as invalid (spec/permissions.md §6), not purged or expired since, is may-hold for that node, unless the node dropped another delta of it otherwise (spec/commits.md §5): then it is must-not-hold, as above.
  - **May-hold bodies**: nobody acts on them except a compactor dropping them once per body (commit and delta set, §7).
  - **Tombstones**: a tombstone only keeps the identical blob out, against stale relays and bundles. A host reporting an entry a node removed within that node's tombstone, by an announcement or by accepting its upload (an answer arriving after the removal or lost with the connection, a stale push), whatever the entry is: the node counts it present there and judges it as any other entry, so that host's copy is deleted too. The node does not fetch or store it for that (bytes it receives give only their salt). The node keeps what the entry was (its kind: commit and parts, chunk, linked blob; its prefix salt; and whether it is a certificate copy) with the tombstone, across restarts. An upload in flight does not keep an entry the node would otherwise drop.
- A partial node repeats reconciliation until a pass changes nothing, since newly received data may grow its closure.
- Chunk and tree-node blobs of large atomic values may be fetched lazily, by local policy; pages of a delta are fetched before its commit is applied (spec/commits.md §4).

## 7. Compaction and deletion
- **Compact**: a node that may write an aspect uploads snapshot commits (spec/commits.md §2) for the aspects it compacts, then drops the bodies they cover and deletes at hosts those it may purge.
  - It drops a body once it is out of history and nothing reads it on its own (spec/commits.md §5 Covered: a live delta stays): its keep-at-least bound (spec/commits.md §5) is past on its clock. Any held valid writer's snapshot covering it drops it, the purge right or not (spec/commits.md §5 The setting); deleting it at hosts needs the right and waits `MAX_DRIFT` more (spec/commits.md §5 Keep at least).
  - **Other nodes**: every node that holds a snapshot does the same for its bodies, deleting at hosts where it holds the right, judging a body again while it is before that time or not established covered or uncovered.
  - **Live writes**: a body with live writes (in any of its deltas) is deleted at a label only while other entries under it carry each of them, per delta holding one of its own: a snapshot under the label covering it (a held delta by the join of spec/commits.md §5 Covered, whatever carrier was recorded for it before), or another blob of the commit holding it that is not must-not-hold and not an identical body with a higher blob ID (of two duplicates the higher goes without waiting).
  - **No carrier**: a right holder that must delete a body with live writes and finds no carrier uploads a covering snapshot first when it may write the aspect, unless it holds a blob of the commit that will carry them (a purge's rewrite).
    - A host refusing that blob, a strict subset of the body, for the label's cap (code 12): it is uploaded again naming the body as replaced (§5).
  - Chunk blobs still linked from a retained version are kept.
  - Two snapshots covering each other (equal `ts`, spec/commits.md §5) are covered-equal; a compactor drops the one with the higher commit ID.
- No node snapshots a signal (spec/commits.md §5 Signals): its bodies leave by expiry, purge, as invalid, or out of history.
- **Sweep**: before a snapshot of a durable content aspect (not role-class, not `retention^.0`), a node resets, in one ordinary content commit, each map entry and list element (at any depth below live ones) that is not live (spec/crdt.md §5.6, §5.7) and holds a write beside its removal or an expiry or purge it holds of its creation.
  - A write here: in a map any write under a key, else a value-carrying one or `W`.
  - A record merely lacking its creation is left: the creation may arrive.
  - A reset so repeated stays if the first remover turns out invalid.
- **Repair**: a node that may write an aspect of a thing in a label's closure, past its first sync there (§6), acts on each entry of a suspect list a connected peer sent it for the label (spec/permissions.md §4) whose digest differs from the node's own digest of that aspect, if it holds state of the aspect.
  - It writes a snapshot of the aspect from its whole state (spec/commits.md §2) and places it like any must-hold body, unless it already wrote one from that same state for that node.
  - It judges each entry once per suspect list.
  - It SHOULD report every entry it judged (a diagnostic), repaired or not.
- **Duplicates**: of two blobs of one commit with the same delta set under one label, a delete-key holder deletes the one with the higher blob ID. Of two at a host where one counts as lacking (§5), that one, and it counts as no copy of the other.

## 8. Subscriptions
A connection may subscribe to labels. The peer then pushes new log events (with blobs, wraps and stamps) as they arrive (held back for a slow subscriber, §6 Flow control), in the cursor-reply format, until the open ends (§5).

## 9. Ephemeral commits
- **Sending**: a node's own writes of ephemeral aspects (spec/data-model.md §2) are ephemeral commits (spec/commits.md §2) like its durable writes are durable commits.
  - **One commit**: a write's ephemeral writes are one commit (spec/commits.md §3; in session form, without `expires` under the node's session, with one under its second session, spec/crdt.md §2.1).
  - **Delete**: a delete, and an undo of a creation (spec/crdt.md §4.6), writes no ephemeral commit: the writing node drops the thing's ephemeral state locally. Limit: other holders keep the thing's ephemeral values until they restart or the values' own lifetimes end (expiry, spec/crdt.md §4.7); the thing is in none of the groups it was taken out of. A copy of a dropped commit reaching the writing node again applies again.
  - **Ephemeral signals**: a write's ephemeral signal writes go as one relay-only commit, at once.
  - A commit whose delta does not fit a blob is refused at the writer (spec/commits.md §2).
- **As durable bodies**: an ephemeral commit's bodies are judged, placed, uploaded, relayed and deleted exactly as durable bodies are (§3, §5-§7): under the labels of the closures its things are in, must-hold while established uncovered, stamped under the head's write key at each upload (so a refusal under an older key, code 9, is answered by the next pass under the new head), relayed or deposited by readers, deleted at a label once a snapshot there carries them, re-placed as a fresh encryption where the old blob is tombstoned.
  - A thing no closure holds syncs no more (§3): nothing of it goes anywhere, and its bodies under a label it left are deleted there like a durable thing's, by a node that held the body in that closure (after a start a node's view of the closure is what has arrived so far: it deletes nothing for being outside it).
  - **Storage**: what differs is storage and what follows from it. Every node holds ephemeral commits, their blobs and every record about them (entries, presence, tombstones, carriers) in memory only (Holding).
  - **Held at a host**: an entry counts as present at a host only as learned on the connection up now (a restarted host lost its ephemeral entries and its durable log says nothing of it). A node's first Sync of a label on a connection lists the ephemeral entries it holds there as `gained` (when they fit the message; §6), the peer asks for those it lacks, and the rest count as present there once the Sync ran through.
  - **After a start**: a node's first sync of a label at a host after it starts reconciles the live sets first and keeps its cursor (the entries the cursor passed are in no memory any more). A connection ending before every entry that reconciliation found missing was received reconciles again on the next.
  - **Tombstones**: an ephemeral entry's tombstone lasts `MAX_DRIFT`, at hosts (§5) and at nodes alike, and an announcement of a blob tombstoned here within that time is not fetched (§6 Tombstones).
- **Coalescing**: before a pass sends under a label, two or more of the node's own plain (no `expires`) session-form commits of this session on one aspect not yet placed under it go as one snapshot of their join (spec/commits.md §2; frontier over the session up to the last of their counters): they are then covered here and never go. A body the snapshot does not cover (behind an invalid one of its session) goes as it is, and with a snapshot among them all go as they are.
  - **Waiting**: while an own ephemeral upload under the label is unanswered on the connection, the node's later own ephemeral commits there wait (judged again once it is answered), so an aspect goes up as about one entry per round trip whatever the write rate.
  - Expiring writes are not coalesced: a snapshot never carries an expiring value (spec/crdt.md §8).
- **Holding**: every node holds the ephemeral commits it makes or receives, their blobs per label and their records, in memory only, never in its store or a bundle, until it restarts or they go (below).
  - **Verification**: a received one is verified as any commit (spec/commits.md §4) before its blob is kept, served or uploaded anywhere.
    - One whose author's record, a part's thing's record or a chain it needs is not held is unjudgeable (spec/commits.md §4): nothing of it is kept; its entry counts against the node's cap below until it is fetched again.
    - Parts are judged (spec/permissions.md §5.2).
    - A session-form one applies atomically and an invalid part is un-merged (spec/crdt.md §4.6).
    - A part past its `expires` is held as its leftover, value-less, at every node (spec/crdt.md §4.7), one arriving past it included.
    - An ephemeral commit more than `MAX_DRIFT` ahead of the wall clock waits as a durable one does.
  - **Forgetting**: a node forgets an ephemeral commit whole, header included, once none of its parts is held any more (each covered or superseded; a leftover is held until covered or superseded) and none waits, keeping of its header only what deleting its entries at hosts needs while it has any.
    - A copy of a forgotten commit arriving again applies and goes again by the same rules.
- **Compaction**: any writer of the aspect compacts (spec/commits.md §2, §5).
  - **Trigger**: a node writes an ephemeral snapshot of an aspect once the session-form bodies it holds of it that a snapshot may cover (without `expires`, or held value-less past it), two at least, cost more than twice a snapshot of it, each counted as its deltas' bytes plus a per-part and a per-entry charge (local policy, what a holder's cap and a host charge). A host's refusal triggers nothing.
  - **Dropping covered bodies**: every node drops a held body a held valid ephemeral snapshot covers (spec/commits.md §5) once its keep-at-least bound passes (spec/commits.md §5 Keep bounds): at once where no setting keeps history for the aspect of any of its deltas.
    - Exception: a node drops a body it authored only under one of its own snapshots (local policy).
    - A snapshot stamped no later and covered by another goes the same way.
    - Of covered-equal snapshots the higher commit ID goes (§7).
  - **A snapshot turning invalid**: a node whose held valid snapshot turns invalid reconciles the label (§6) so the copies holders still have reach it again. If it may write the aspect and still holds a valid part of it, it writes a snapshot of the aspect from its state and uploads it (a new commit, which a host's delete tombstone on the old entries, §5, does not stop).
  - **Frontier**: a snapshot's frontier stops below a body of a session that is invalid or missing at the writer, so that session's later bodies are not covered until it is valid and held there.
  - **New sessions**: a node one of whose session-form writes under its current sessions turns invalid begins new sessions (spec/crdt.md §2.1) for what it writes from then on.
  - **Deleting at a host**: a writer deletes the entries of a dropped commit at a host (spec/crypto.md §7, level 3) once an entry of a snapshot covering it is held there, or names them as replaced (§5) in that snapshot's upload. One dropped for no coverer (expired, its things freed) goes at once.
  - **Superseded parts**: a node also drops a held part of a plain ephemeral commit that has `expires` once the part carries no reset (spec/crdt.md §4.2; tombstones included) and is superseded by a valid held part of another plain ephemeral commit of its author on the same aspect, whatever else either commit holds.
    - The superseding commit and part qualify when all of these hold:
      - its `expires` is not earlier;
      - it carries no reset;
      - each of its writes has a later `ts` than every write of the superseded part and is not into a record it does not create;
      - its delta joined with the superseded part reads (spec/crdt.md §4.4) as it does alone.
    - This is judged when the superseding part is held valid (on arrival, at its build, or when it turns valid) and when the superseded part goes value-less at its expiry.
    - The dropped part's writes then vanish whole, as if never applied, at every node, its author included, so a later removal or undo of the superseding write does not show them again.
    - Once a commit with a part so dropped is forgotten, its author deletes its entries at a host once a superseder or coverer of its parts is held there, and no other node deletes them.
    - One whose every part is superseded on arrival is not held.
    - An own write with `expires` superseded by a later own write before it was sent is never sent.
- **Caps**:
  - **At a node**: per label, a node holds at most a configured number of bytes of ephemeral bodies from others, each counted at an estimate of the memory it takes held (decoded, with the records beside it; local policy, at least its encoded size).
    - A commit is decoded only as far as a bound on that estimate made from its bytes (local policy) fits the room left under the cap, and applied only within it; others are not applied there.
    - An entry refused so is fetched again once the label's held bytes dropped below what they were at the refusal, one that can never fit (larger than the whole cap) not at all.
  - **At a host**: a host carries a label's ephemeral entries up to its cap (§5). An entry it refuses reaches no holder through it until room appears. The refused node uploads it there again later (local policy; room also appears without a log record, as entries expire).
- **Relay-only commits**:
  - **Dropped unopened**: a node drops a relay-only blob unopened when one of these holds:
    - it is larger than `MAX_RELAY_BLOB`;
    - its prefix expiry is passed or more than `2 × MAX_DRIFT` ahead of its wall clock;
    - the node received that blob ID under that label before its expiry (remembered for at most a bounded number of blobs: past it the earliest-expiring is forgotten and its expiry becomes the label's floor, at or below which blobs are dropped).
  - **Delivery**: it verifies the rest like an ephemeral commit and tells its valid ephemeral signal parts to listeners once (spec/data-model.md §2). It holds and re-uploads nothing.
  - **Replay**: it remembers delivered relay-only commit IDs until their `ts` is `MAX_DRIFT` old, at most `MAX_DELIVERED` (past that the earliest delivered is forgotten and its `ts` becomes its author's floor unless lower, at or below which that author's relay-only commits are dropped), and drops relay-only commits whose `ts` is more than `MAX_DRIFT` from its wall clock.
  - **Co-reader peer**: a co-reader peer serving the label passes a verified new one on, stamped as received: from a host to the readers sharing the label (§10, Stream), from a reader to its other readers and to the label's hosts it syncs with.

## 10. Transport and addresses
- Sync runs over any ordered, bidirectional byte stream with confidentiality and an authenticated peer key.
- A transport handshake has no deadline of its own beyond the transport's idle timeout; a host MAY close a connection whose peer sends no Hello (spec/wire.md §11.1) within a local policy bound.
- A host **address** is a transport URL plus the host's static public key; a client MUST check the host's key against it.
- **Keys and reach**: clients connect to hosts with an ephemeral transport key per connection. A node's dialable P2P key is separate from its signing key and published only in `reach.0`, together with its global addresses, its relays and the account it says it belongs to (for dialing only, never proof); `reach.0` goes under its account's D's home label only (target, issues/account-signing.md step 8), so only its own account's nodes read it. Other nodes learn a dialable key and addresses from a link, a configured address, a connection, or the serving-node listing of a contact's profile (for dialing only). Other addresses are never published; nodes exchange them on a connection (hole punching), or LAN discovery finds them.
- **`quic://host[:port]`** host addresses (port 4040 when absent, an IPv6 address in brackets):
  - QUIC v1 (RFC 9000, RFC 9001) with TLS 1.3 only, ALPN `osis`, 0-RTT MUST NOT be used.
  - Both sides MUST authenticate (client authentication is mandatory) with RFC 7250 raw public keys: an RFC 8410 Ed25519 SubjectPublicKeyInfo, signature scheme `ed25519` only, no certificates.
  - The host's key is the address key; a client's is fresh per connection, or a host's own address key when it dials another host.
  - SNI is ignored.
  - Each sync session (spec/wire.md §11.1) runs on a bidirectional stream the client opens; the dialer closes the connection.
- **Node keys**: a node's dialable key and its LAN transport keys are Ed25519 public keys (RFC 8032), each with a 32-byte seed as its transport secret. A node dials other nodes with an ephemeral transport key and proves the actors it acts for inside the session (Connection proofs).
- **Connection proofs** (bytes and the exchange: issues/net-shared-set.md, Account proofs across rotations): each side proves the actors it acts for over the connection's challenges, both ways, and to a side that already knows them only (spec/requirements.md, Offline and network):
  - its account by a signature at an epoch, with the signed rotations of that account the verifier lacks; a refusal carries the verifier's rotations the prover lacks. Both sides judge them by spec/permissions.md §5.4 alone, no timestamp read;
  - a key actor (a link key) by its signing key, matched to a static entry the verifier holds;
  - its own node key only to nodes of its own account: a dialer when the key it dials is, by the `reach.0` it holds, a node holding a role on its account's devices actor D; a listener when the dialer proved its account or such a node. A verifier takes a node proof as the peer's node only when it is such a node of its own account; a node of another account is the account it proves.
  - **As built**: an account's proof is a signature by its epoch's key; the verifier counts it only at an epoch open by the rotations it holds, or, for an account it holds nothing of, at the first epoch (the creation record's key). Carrying the rotations a verifier lacks and the refusal are not built: a verifier that lacks the signing epoch's rotation proves no account.
    - A removed node keeps the seed of the epoch its removal's rotation closes: it proves the account only to a verifier that does not hold that rotation.
  - **Order**: the dialer proves first, after the listener's Hello, only on a connection to a key it chose to dial; the listener answers with its own proofs only if the dialer proved a **known actor**, else with none: by the rosters the listener holds, an actor holding a role on a thing other than itself that is not private to an account other than the listener's. A thing is **private** to account P when its reader actor is P or P's devices actor D (spec/permissions.md §1): P's own actor, D, its home and what only P's nodes read. Holding P's private things makes P and its nodes known only to P's own nodes; a thing P made and shared counts as any other. A key actor proved on a connection is the key actor of a static entry its Hit names whether it is known or not (Shared set). A proof is never sent unasked (spec/wire.md §11.2, Prove).
  - Which side dialed and what carries the connection change nothing else.
  - Nothing a connection proves comes from group data; the serving-node listing on a profile is for dialing only, never proof.
- **Pair key**: two nodes that each proved a known actor to the other (Connection proofs) keep one record of each other, found by a 32-byte pair key `r` known only to the two. No node key finds a record.
  - After `Proved` the dialer sends `Resume` (spec/wire.md §11.2): a fresh nonce and, for each of its records naming a proven actor of this session (most recent first), `BLAKE3(key = r, "resume" || listener static key || dialer challenge || listener challenge)`, challenges as sent in Hello.
  - A record is honoured only while a proven actor of this session is named by it and known here now: an account proved at an epoch open here or a key actor.
  - The listener answers `BLAKE3(key = r, "resumed" || listener static key || dialer challenge || listener challenge)` of the first listed record it holds, else none. An absent or unexpected answer finds nothing.
  - On no match, both sides make a new record with `r = kdf("pair key", dialer nonce, listener nonce)`, written before the listener's answer goes (listener) or when the answer is read (dialer).
  - The listener sends its answer before any message of the connection's shared set.
  - A connection that proved no known actor keeps no record; where such a connection needs a pair key it is `kdf("pair key", dialer challenge, listener challenge)`, kept nowhere.
  - `r` and the nonces cross only inside the connection's own messages. Two connections to one peer use one record (Shared set).
  - A record keeps the shared set S (each member with the credential class and beacon it was opened by, none for an open by J, its `until` while it is being ended, and where it is in the stream: at the stream's cursor, or joining from its own position), `acked_pos`, this side's last filter generation sent and acknowledged with its whole entries and additions since, the peer's latest filter, the stream's cursor, and where each member that left S stopped. A connection that takes a record starts from all of these; a session proving other actors than the record names starts with every credential pending and a whole filter.
- **Agreement** (bytes: spec/wire.md §11.2 Digest, Members): on a connection with a record, each side's first message after `Resumed` is `Digest`, the xor over the record's S of `BLAKE3(key = r, sync_id)`, computed from the record before anything else on the connection. A side compares the peer's digest with the one it sent, once a connection.
  - On a difference, each side sends its S as `Members` pages on reading the peer's `Digest`, before acting on any later message. On the peer's last page it closes each member only it holds, keeping no position for it (its rejoin is from the start), and re-marks pending (Testing) every sync ID in exactly one of the two lists.
  - No Offer is sent before the peer's `Digest` is read, and no Pull before the digests matched or the peer's last `Members` page is read.
- **Shared set** (bytes: spec/wire.md §11.2 Beacons, Offer, Lost, Shared, NoRecord): the sync IDs two connected nodes share, found per connection and judged on what each holds now; each side of a connection after the proof exchange runs one, under a pair key `r`: the record's, or, on a connection with no record, `kdf("pair key", dialer challenge, listener challenge)`, kept nowhere.
  - **Rule**: a node shares L with a connected peer exactly while, on what it holds now, the peer may hold L: an actor the peer proved on this connection is a current holder of L, or the peer showed an admissible credential of L.
  - **J** of L for a connection: holder if a proven actor holds L's read role through the rosters held here; departed if a proven actor once did and no path remains; else unknown. A node key proves no account: only the account's own proof at an open epoch counts as the account.
  - **Admissible** credentials: a node's read secrets of L at a current epoch (spec/crypto.md §4; with none current, the newest held; for a sync ID an inbox blob named, before its `label.0` is held, the secret its box gave), and the static entries of key actors listed on L's roster held here or the key actor its link or card follows; none where J is departed. Of a sync ID a node keeps and cannot read (it holds no read secret of it, §4): its head's sync key, its deposit key and every key of the head's claim set (J is unknown there).
  - **Beacon**: `BLAKE3(key = kdf("beacon", match, L), r)`, `match` the credential's value (the read secret, the static entry, or the raw sync or deposit public key). A filter entry is the first `f` bits of a beacon, `f = ceil(log2(n)) + 8` for a whole filter of n entries.
  - A **filter** of beacons of the admissible credentials goes to every connection, a node's credentials of the sync IDs it reads only to a peer that proved a known actor (a change of that makes the next generation whole). A side sends one generation at a time, the next after the last is answered (an Error answering it, or an Offer, is a refusal of it; a refused generation is followed, after `resync_ms`, by a whole one): the first whole, later ones additions (`base` the last generation the peer acknowledged, on this connection or an earlier one of the record) of the sync IDs whose credentials or roster changed; a whole one replaces additions once they pass its entries. On a connection with a record the first generation is additions of the sync IDs whose `changed_at` is past `acked_pos`, sent even when there are none, unless the peer acknowledged no generation of the record or not the last one sent (then it is whole). The receiver keeps the peer's latest filter in the record. A dialer that keeps no record for this listener sends NoRecord; the listener then runs the set under the connection's pair key.
  - **Testing**: a side tests its own admissible beacons of the sync IDs it reads not yet acknowledged and tested (`changed_at` past `acked_pos`, issues/net-shared-set.md Testing) against the peer's latest filter, at each filter arrival and each change of what it holds, with at most one Offer unanswered. `acked_pos` rises, durably in the record, only with no Offer unanswered, to the lower of the position the peer's last acknowledged generation reached and the position tested. **Re-marking** L for a record (a `Lost` sent or received, a digest difference) lowers its `acked_pos` and tested position below `changed_at(L)` and makes a test due; no other record changes.
  - **Offer**: Hits first (`BLAKE3` keyed by `kdf("beacon hit", match || L)` over a side byte, 0 by a dialer and 1 by a listener, the listener's static key, both Hello challenges and the beacon): it names no sync ID and is bound to its sender's side and this connection. A Hit opens L only if it is one of the receiver's admissible credentials its filter to this peer shows (a credential of a sync ID it reads only where the peer proved a known actor) and shows its class's proof: for a static entry, a proven actor of this connection is the entry's key actor; for a sync key, it carries an open signature by that key (§5 Open) over the receiving side's Hello challenge and the listener's static key; a deposit key's opens nothing. The answer carries a tag (keyed `kdf("beacon reply", match || L)` over the same bytes with the replier's side) and the tester opens L only on a valid tag while its credential is still admissible. For a static entry the answer also carries the head's entry box for that entry and the path to the head (spec/wire.md §11.2, Offer), at a node that cannot read L from the steps and claim sets it keeps; the tester takes the box's read secret only when the path verifies from its genesis step and the secret derives the head's sync key, as for an Open's box (§5), and opens nothing on a box that fails. Then ByRole, `[L, [Hit*]]`, for L a side holds that J judges the peer holds: opened when the receiver holds L and J is holder, or a listed Hit is its own of a read secret or a static entry (a static entry's only where a proven actor of this connection is its key actor); an accepted ByRole opens L at its sender while J is still holder there.
  - **Deposit** items (`[L, blob, wrap, sig]`, signed as a Deposit, §5): an inbox blob for an inbox L (§3) whose `keys.0` lists no host goes as a Deposit item, at any time after the peer's `Digest` is read, one unanswered per connection, only where J of L's actor is holder. The receiver takes it (answer 0), as a host's deposit is taken (§3, §5), when it holds L, an actor it proved on this connection holds L's read role, the signature verifies under its head's deposit key and the blob is of the durable class; one it holds or dropped is answered 0 and changes nothing; past its peer budgets it is refused for now (5); else 14, whether or not it holds L. At the sender a 0 ends the deposit; refused for now is sent again after the back-off of §5 Sending; 14 is signed again with the current deposit key and sent again where that changes the signature, else not sent on that connection again until what the sender holds changes. One not taken stays pending (§3). A node that keeps L and cannot read it takes a Deposit item for L as a Deposit (§5: the head's deposit key, budget, rate, caps), answering 0, refused for now (4, 5, 12) or else 14, whatever the connection proved.
  - **Lost**: a sync ID the sender no longer shares here, with where it stopped for the receiver: the receiver's **reported position** for it, or the member's `until` where lower (none where it reported none). A reported position is one the receiver stored: on a connection, the first Pull's cursor and each join's position in the first Pull naming it, then the cursor of each Applied, each as of the message that position covered (a join's own position until the message merging it is covered); reported positions last the connection. At any change of what a node holds, and when a connection takes a record, it re-judges every member: a holder stays, a member opened by a credential stays while that credential is admissible; a member opened by a credential no longer admissible whose peer's actors J judges neither holder nor departed is **ended**: it gets `until`, the highest position at which an entry in L of a rotation superseding that credential's epoch was first logged, else the node log's end, judged in the step that applies the change, before any PullReply or Stream of it, for every record holding the member whether connected or not; any other closes with a Lost. An ended member is served only its events at positions up to `until` and the later events of entries the log first held at or below `until` (a Fetch of it only those entries), none of its ephemeral or relay-only entries, and closes with a Lost naming `until` once its reported position is at or past `until`. A member of a sync ID a node keeps and cannot read stays while its credential is the head's, and is otherwise ended with `until` the position of its head's event when judged, before the node answers anything after the head moved. A member ended and then judged holder or admissible again is no longer ended. The receiver keeps the Lost's cursor as where the member stopped. A `Lost` is never sent again; one lost with its connection is found by the next digest.
  - A connection with no shared set answers its requests Error 14.
  - Two connections of one record, whoever dialed each: a direct one (not relayed, §10 Relayed connection) stays before a relayed one; among two alike the one with the smaller `BLAKE3(key = r, dialer challenge || listener challenge)` stays. The other closes, at both ends, whatever order they arrived in. A node whose dialed connection closed so does not dial that peer while the other lasts.
- **Stream** (bytes: spec/wire.md §11.2 Pull, PullReply, Stream, Applied): a node that reads its shared set's sync IDs pulls them from its peer by one stream over the peer's **node log**.
  - **Node log**: one log per store over every sync ID it holds: an event when an entry becomes servable (row and bytes held) or its wrap or stamp changes, when one is removed, and when a sync ID's served head moves, at the next position of one sequence. It keeps each entry's latest event with the position the entry was first logged at, and each sync ID's latest head event, and drops a deletion event `TOMBSTONE_LIFETIME` after it was logged; it is never trimmed by position. Entries of the ephemeral class are in its memory part, ordered by a counter of their own and lost at a restart.
  - **Cursor**: an AEAD seal under a key of the log of (log ID, incarnation, position). The first append after a store start draws a new incarnation and records where the one before ended. A cursor that does not open, is past the log's end, or names an incarnation the log does not hold at that position names no position.
  - **Reading**: a server reads its log in a transaction of its own, after its served heads are logged, filtered by the connection's shared set and by bytes held. A reply covers a position only for members it scanned to it, and a requester stores a cursor only after applying what it covers: an entry announced without bytes is applied once its bytes are held (or it is no longer wanted there: removed within its tombstone, or refused by its ephemeral cap; or this source no longer holds it: its deletion, or a fetch it answers without the entry or skips).
  - **Flow control**: a requester keeps no entry for an announcement without bytes until its bytes are held; what a stream owes is kept with the stream only. A stream waiting on a local bound of positions or owed bodies sends no Pull and does not apply a Stream with a cursor; after one it did not apply it applies none until its next PullReply.
  - A member entering the stream (newly open, or open again) joins it from where it stopped on this connection's record, else from the start, with its live ephemeral entries listed (no cursor names one). A member that stops being open leaves the stream at the position it holds before the requester applies more. A stream or join from the start never deletes an entry the requester holds that it does not list.
  - **Both sides pull**: each side pulls the members of S open on its side that it reads, whoever dialed (a node that cannot read a member serves it from what it keeps, §4, and pulls none); the stream's cursor and where each member stopped are kept in the connection's record. A connection that takes a record pulls the record's members from where the record holds them, with no join for a member at the stream's cursor. Readers do not upload to, open at or delete at readers: a node's own writes reach them by its stream, so a node places its writes in its own store while a reader can pull it, whatever hosts are connected (§5).
  - **Applying**: events are judged by the requester's own rules: a stamp counts only under the head it serves; a deletion says only that this source no longer holds the entry and is not acted on (only a right holder's drop counts, §7); a head event is not acted on (heads come by `label.0`). Unstamped entries a reader brings that do not open count against a bound on what peers may make it store (local policy, as a host caps storage, §5), and past it are not kept.
  - **Bodies**: a requester with another source of any member asks `inline_limit` 0, and Pulls again with 0 when a member gains another source; it fetches every body announced without bytes (Fetch with a top-bit id, spec/wire.md §11.2) from one source at a time, the next source sharing the sync ID only when one fails (answers it with none, refuses or skips the Fetch, spec/wire.md §11.2 Pull); a body a stream announced that is held nowhere and asked nowhere (a fetch lost with its connection) is fetched from that stream's source. One rule holds across sources, hosts and readers alike: a blob counts as asked while a fetch of it from some source is unanswered for less time than the Stall rule (§6) waits; past that, it is also fetched from another source that has it (a host that announced it, or a stream that announced it) and is not asked it yet, this again for each source in turn, and whatever waited for it (a host fetch skipped, a pass) goes on as if it were not in flight; the first answer holding it settles it. An announcement without bytes in a Stream with no cursor is ignored.
  - **Relay-only entries** (§9) go to each reader sharing the label as a Stream with no cursor; at a node that cannot read the label, those uploaded to it and admitted (§5 Relay-only) go so to each other connection sharing it.
  - **Reports**: a server asks `report` on every PullReply and Stream that has a cursor and carries events, and on one that brings an ended member the requester tracks to its `until` with no report there awaited (a Stream then goes even with no events); the requester answers each with Applied once it applied what the message covers (its bodies held) and stored its cursor. A requester applies in order, so a report covers every message before it. A node closing a connection to a peer it no longer wants does so after the step's re-judging and settling, so the Applied that step owes goes first.
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
  - **Relayed connection**: TLS 1.3 runs over the forwarded bytes as on a direct connection (the dialer is the client and pins the target's key, ALPN `osis`, raw keys, no session tickets, no early data), records exactly as RFC 8446 frames them. The plaintext starts with an `addr` from each side, which each sends before reading the other's: its own address as the relay saw it (the dialer's from its Dial answer, the target's from its Register answer). Then the plaintext is one session; a relayed connection carries no other. Its end is the TLS close_notify; forwarded bytes ending without one end it abnormally.
  - **Registration streams**: a registering client lets the relay open 2048 streams at once on the registration connection, with a connection receive window at least 2048 times its stream receive window, so forwarded streams it has not read never hold back another. It holds at most 1024 forwarded streams not yet serving an accepted connection (handshaking or queued), ending the oldest past that.
  - **Hole punching**: on a relayed connection the target sends one UDP datagram, the single byte `0x00` (no QUIC packet: QUIC endpoints drop it unanswered), from its listening socket to the dialer's address, and the dialer dials the target's address from the socket it reached the relay from, as a direct connection. Each side uses the address the other sent only if it is unicast (not unspecified, multicast or IPv4 broadcast) with a nonzero port, and global (as `reach.0` defines it) unless the relay's address it reached is not global; otherwise it neither punches nor dials, and the connection stays relayed.
  - **IP consent**: any positive action toward a node (sharing a group with it, making, sending or following a link, accepting an invite, choosing a relay) is consent to show it this node's IP address. So a node exchanges addresses with every peer of a relayed connection.
  - **Switching**: when a direct connection completes after a dialer began using a relayed one, it closes the relayed one and its next dial of that key uses the direct one.
  - **Relaying** is a node's choice. A relay accepts registrations only of the keys it allows, and bounds per source (an IPv4 address, an IPv6 /64) the bytes per second it forwards and its share of relay connections. It sees addresses, volume and the keys dialed, never the data.
  - A `peer://` entry in a label's `hosts`, or a saved peer, is a host like any other address: dialed by its key with the URL's items as hints.
- **LAN discovery** announces nothing stable across networks or meaningful to strangers: a tag and a transport key fresh per network join, never the dialable key.
  - **Tag**: `kdf("lan tag", lan secret, le64(window))` (first 16 bytes), with window = `floor(unix ms / 600000)`. The 32-byte random lan secret is in `reach.0`. A node matches tags of the nodes whose `reach.0` it holds (its own account's) for the current and adjacent windows; finding other accounts' nodes on a LAN is issues/net-connect.md's (target, issues/account-signing.md step 8).
  - **Joining**: a node joins anew (a fresh transport key and listener, announced at once and a few more times in its first seconds) whenever its network may have changed.
  - **Announcement** (provisional): a UDP datagram to port 47380 on each address family the node has, as an IPv4 broadcast (255.255.255.255) and an IPv6 multicast to the link-local all-nodes group ff02::1 on each up interface with a link-local address, and to any further addresses configured, of exactly 124 bytes:

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
- **One key**: a node listens under one transport key, its dialable key, at every listener but its LAN ones (a fresh key per join) and its unix socket (a key by uid): the URLs its operator chose, its `peer://` listener. Every listener serves everything the node serves: data it stores for others (§4, §5), node-to-node sync and the client port (spec/wire.md §11.2 kinds 24-29). A connection's `Hello` static key is the key of the listener that took it. The key changes only by hand, and every listener moves to the new one.
- **Served connections**: a node bounds the connections it serves at once (local policy). At the bound a newcomer takes the place of a connection that shares nothing (no open, no member of its shared set, no authenticated client), the oldest of the sources holding the most such, else of the newest of a source holding at least two more connections than the newcomer's; else it is closed. Below the bound none is closed for sharing nothing. A node bounds the memory it holds for the connections it serves, its transport's buffers included (local policy): in each direction over all of them, bytes of frames received and not yet run or answered, partial ones included (past it the connection holding the most is closed) and bytes written and not taken by the transport. The latter, with the reply allowances of requests it is answering, is never passed: a connection's reply, push or own request goes only within its share of the bound and the bound's room, else the request waits, in order, and the node reads no more of that connection meanwhile; one holding nothing may take one reply past its share, in turn with others waiting for the bound's room. While one waits so, the node closes connections whose bytes the transport takes none of, the one holding the most first, and, once it has waited half the requester's stall time, the connections holding the most whatever they take, until it fits.
- **`unix:///path`**: a path socket (never an abstract one), no TLS.
  - Each side reads the other's uid from the kernel (`SO_PEERCRED`) and accepts only its own uid.
  - A side's key for the address is BLAKE3(`"osis v1 unix peer"` ‖ be32(uid)).
  - Only a local client dials one; a node never dials a `unix://` address taken from synced data.
  - A session on it is a **main session**, acting as the node's main actor (Auth without secret); a session on any other transport never is, whatever key it presents.
- **Client-actor session**: a session on a keyed transport, whose dialer pinned the node's key, that sent a current bearer secret in Auth (spec/wire.md §11.2).
  - The node acts as its client actor: it signs the session's commits as its account, with that actor in the header's actor field, and holds them to that actor's rights itself, since receivers judge only the author account's (spec/permissions.md §5).
  - A client's secret is never sent on another transport.
  - A client whose connection ended dials again with its session id unchanged, sends Auth, and resends each write that had no answer, marking it (spec/wire.md §11.2). A node that no longer remembers it answers that its outcome is unknown.
- **Group source**: a node MAY read and write a group through another node it is a client of (the group's source).
  - A thing in a group sourced at another node goes there, whatever else holds it; the copy this node holds never answers.
  - A write on it is refused while a group carrying it (§3) syncs here or is sourced at another node.

## 11. File bundles
A bundle is a one-way log replay for a set of labels: registration paths, entries with wraps and stamps, blobs, deletions (spec/wire.md §12). An importer treats it as a peer with no cursor.
