# Sync: sync IDs and the store
> Summary: Area 2: blobs, sync IDs and their role keys, steps and claim sets, `sync.0`, the node's store per sync ID, and the operations a store takes (Register, Behind, stamps, wraps, Delete, expiry, relay-only, caps).

**Principle:** a sync ID belongs to its thing: made once from the thing's own secrets, its keys derived from the thing's current role secrets, its path of steps verifiable from genesis by any node without trusting a peer. A store takes only what verifies under its own head.

## 1. Blobs
- A **blob** is one of:
  - an encrypted commit (header plus unpurged deltas; spec/commits.md);
  - an encrypted chunk, tree node or page (spec/data-model.md §6, spec/crdt.md §8, a header list spec/commits.md §1);
  - an inbox blob (spec/sync-inbox.md §2).
- A node keeping S unread cannot tell them apart except as §5 states.
- **Layout**: **clear prefix** || ciphertext. The prefix holds a salt, an optional expiry `T`, the blob's **class** and the delete-key commitments, one per level (spec/crypto.md §7). Ciphertext: spec/crypto.md §5. Bytes, padding, **Blob ID** and the `MAX_BLOB` bound: spec/wire.md §5.
- An add event or fetch answer whose bytes do not hash to its blob ID is ignored, whoever sends it.
- **Class**: durable, ephemeral or relay-only, set as spec/wire.md §5 states; how each is held: §5, §6 Relay-only.
- **Several blobs of one commit**: one commit may travel as several blobs (purge rewrites, certificate copies, concurrent re-encryptions): same header and commit ID, each with its own key, salt and ID.
- **Prefix of a commit encryption**: every encryption of a commit computes its prefix from the header and the aspects its sections list (spec/wire.md §4):
  - expiry = the commit's `expires`;
  - one commitment group per distinct delete-key set among those aspects, blinded by the new salt (spec/crypto.md §7; spec/wire.md §5);
  - a header-only blob (spec/commits.md §5) has neither.
- **Chunk reuse**: a chunk reused by a later delta keeps its blob and prefix, unless it must be re-encrypted.
  - It is re-encrypted when one of these holds:
    - its expiry is earlier than the new delta's;
    - its commitments to the thing's delete keys (levels 1 and 3) are not exactly those of the keys the reusing delta lists;
    - it commits to a level-2 key other than the reusing delta's, and that delta lists no level-2 key or only a level-2 key;
    - its link's salt or delete keys are not what its prefix bears (spec/data-model.md §6): a reused link is copied verbatim.
  - Beside a level-1 or level-3 key an author-chain commitment need not match.
  - The link alone decides it: its link blind and the thing give the commitments (spec/crypto.md §7), whichever commit introduced the chunk and whether the node ever held that commit.
- **Repair** of a chunk or tree node blob:
  - A node repairs the blob when all of these hold:
    - a held, unexpired delta of the node's own commit or compaction snapshot links the blob through its large values' trees;
    - every source of S it reached has deleted the blob (a purger that had not seen the reuse), and its own store no longer holds it;
    - the node may write the aspect and holds the blob.
  - It judges these by its view once it has applied every entry of S it can open (those it learned of with the deletion included) and holds no commit pending (not parked) on the aspect.
  - To repair, it writes each large position of the aspect's current value whose tree holds the blob again, whole and without a reset (`put_new`, spec/crdt.md §5.6), reusing every other chunk and re-encrypting that blob, with that delta's retention and expiry (a snapshot's: the aspect's default retention, no expiry).
  - How often is local policy.

## 2. Sync IDs and role keys
- **One sync ID per actor**: a commit that gives a thing role secrets of its own (spec/permissions.md §3) MUST also create its sync ID (unless it already has one) and record it in `sync.0`, in that one commit. That sync ID is the thing's **home sync ID**, for its life: holders are removed, the sync ID is never replaced or retired.
  - Every holder of a role on a thing with secrets of its own syncs it through that sync ID, whatever else holds the thing.
  - A plain thing has none: it syncs under the sync IDs of the groups holding it (spec/sync-judgement.md §1). Key actors (nodes, link keys) have no role secrets of their own and so no sync ID: a link key reaches its K's sync ID from its link text (§3 static entry), a node through its account's secrets or pairing.
  - The home closure holds the actor thing and what its `group.0` lists, nothing by record chain.
  - The nearest actor with a home sync ID up a group's record chain carries that group's `sync.0` and `created.0` writes, while the record edges between them stand at the writer (spec/sync-judgement.md §1).
  - A link's sync ID is its K's home sync ID.
- **Sync ID** value: derived from the genesis step's delete public key (spec/wire.md §8). The genesis step derives from the admin secret current when the sync ID is created.
- **Role keys**: Ed25519 keys, the first three from the thing's own role secrets (spec/crypto.md §3):
  - **sync** `kdf("sync key", sync secret, "")`: every holder of sync or above derives it (spec/permissions.md §1);
  - **write** `kdf("sync write", write secret, "")`;
  - **delete** `kdf("sync delete", admin secret, "")`;
  - **deposit** `kdf("sync deposit", deposit seed, sync ID)`, from the deposit seed of the thing's actor (spec/crypto.md §3).
- **Sync proof** of a sync key: `kdf("sync proof", s, "")`, `s` the 32-byte seed of that sync key. Only a holder of the sync secret computes it; holding the public sync key gives nothing.
- **What sync gives**: the sync key, so its holder opens S at peers (spec/sync-opens.md §4), pulls it, holds it and serves it; what its store takes and removes, reading nothing: spec/sync-judgement.md §6.
- **Who grants sync**: the one grant rule (spec/permissions.md §2): an admin, or a holder whose grant carries `invite` at sync or above.
- **Removing a sync holder** is a departure that rotates the sync role (spec/permissions.md §3): the head's sync key moves with the next step, ending every open by the old key (spec/sync-opens.md §6). Removing a reader rotates read and sync.
- **What a sync holder learns**: of the thing, its tid alone, as an opaque identifier (its grant names the thing and its account files it by tid, spec/sync-set.md §4); never its creation record (first admin, link target, record chain), the tids of what it holds (a group's items and subgroups: S's blobs are opaque, and a thing kept unread is a leaf, spec/sync-set.md §2), its roster, content or members. Besides: its sync IDs, the granting account, the path with its claim-set size padded to a power of two, entry counts, sizes and timing, and which accounts' nodes open S with it. Through holder actors: a grant to G on H boxes H's sync secret to G's sync keyset, and a sync holder of G never learns H's sync ID.
  - Limit: the `secrets.0` part it is sent (spec/sync-inbox.md §2) is the whole part of that role commit, its box keys naming each holder the commit boxes (a rotation: every holder of the rotated roles), with the commit's whole header (its time and the aspects it touches).
- A sync grant on D makes nobody a node of the account: a node of P is a node key actor holding read or above on D.

## 3. Steps and claim sets
- **Steps**: a tree. Layout, signature and **Step ID**: spec/wire.md §8.
  - A step holds: sync ID, `prev` (the step ID of its parent; none in the genesis step), the four public keys (sync, write, delete, deposit), a fresh X25519 **step key**, BLAKE3 of the **claim set** (which holds the **entry boxes**), and a signature by the parent's delete key (the genesis step by its own).
  - Each step is carried with its claim set.
  - Every node holding S has one **head** per S: a node reading S the newest step its `sync.0` records (§4); a node keeping S unread the newest step registered with it (§6 Register).
  - An admin issues steps (§6 Steps).
- **Claim set** of a step: padded with random keys to a power of two, in random order. It lists each **reader** M of the registered read epoch (the registrar's newest read epoch at registration): every actor holding its read secret as the registrar knows it at registration (the holders of boxes carrying it, the first admin included while its record edge stands; a holder re-sealed later opens by sync key).
  - A reader is listed by its claim public key (derivation: spec/wire.md §8). M's X25519 key is the X25519 half of its read-role KEM key in the newest `keys.0` of M the registrar holds (a key actor: its single KEM key; an account: its newest open epoch's, spec/crypto.md §3). A non-contributory DH result omits M.
  - A reader that is a key actor other than a node or an account (a link key) is listed instead by its **static entry** (spec/wire.md §8), the same 32 bytes.
  - The registrar erases the step private key after signing.
  - M derives its claim key from its own private key and the step key; it tries each keyset epoch it has held.
- **Entry boxes** of a step: one for each reader that is a key actor other than a node or an account (a link key), sealed to its KEM key (spec/crypto.md §4 sealed form; AD = (sync ID, step key)). Layout: spec/wire.md §7.
  - It holds the epoch's read secret and, when the epoch supersedes one whose secret the registrar holds, the secret of the one with the greatest n, ties by lowest nonce (what its rotation commit is wrapped under, spec/crypto.md §5), and the sync secret whose sync key the step registers (its holder checks it derives the step's sync key).
  - A key actor holding no secret of the thing reads S from the current step; the rotation commit's history box (spec/crypto.md §4) opens the rest.
  - Each secret names its epoch of the thing (spec/crypto.md §4); it is held as that epoch's secret, which establishes nothing.
  - Other readers get none: they read the rotations they missed in order (spec/crypto.md §5), or a re-seal (spec/sync-inbox.md §2).
- **Role keys in use**: a node acts at a peer keeping S unread with the role keys of the epochs that peer's head registers; it derives them from the matching epochs it holds. Every holder of a key in use holds the older secrets through the history boxes, except a holder granted without history, which opens only from its grant's step on: a walk (§6) never strands it for an older step.

## 4. `sync.0`
- **`sync.0`** on a thing with secrets of its own: `map<sync ID, { steps: map<step ID, step> }>`. Role-class, admin-only.
  - Each step is held with its claim set and entry boxes, which an admin MAY drop once the step has been superseded for `ROLE_KEEP` (counted from the `ts` of the write recording its first child).
  - **Owner**: a node takes an entry of a thing g's `sync.0` as g's sync ID only when some step on a verified path from the sync ID's genesis step (each step signed by its parent's delete key, the genesis by its own, whose delete key hashes to the sync ID) bears the sync key of a sync secret of g the node holds. It ignores any other entry wherever it reads `sync.0`; forgetting g without g's secrets, it keeps what a thing it keeps owns. While the node holds no sync secret of g's own (it reads g by derived secrets, spec/crypto.md §3), it takes g's entries as sync ID hints (spec/sync-inbox.md §2).
  - A step enters `sync.0` only by an admin's write; no node records a step on a peer's word.
  - One role commit may carry the `sync.0` deltas of many things.

## 5. The store per sync ID
A node keeps one store of ciphertext for all the sync IDs it holds, read and kept unread alike; plaintext and everything derived from a secret is the engine's, above the store. The store is the truth for ciphertext and the engine's view a cache of it: after a crash between the two, a row with no engine state is derived again and engine state with no row is dropped.

Per sync ID:
- **Path**: the steps from the genesis step to the head (§3): every step's role keys, step key, `prev` and signature; each step's claim set and entry boxes until it has been superseded for `ROLE_KEEP`, longer by policy. A node reading S holds the path its `sync.0` records; a node keeping S unread the path registered with it.
- **Entries**: blob ID; wrap or, for chunk/tree/page and inbox blobs, a random filler; stamp or none; deposited flag; optional pending deletion time. An unstamped entry's charge to the peer that brought it lives in that peer's record (Peer budget).
- **Tombstones** (blob ID) of deleted entries, kept `TOMBSTONE_LIFETIME`; an ephemeral entry's `MAX_DRIFT`, in memory.
- Its events go in the store's one node log (spec/sync-streams.md §3).

Across sync IDs:
- Blob bytes are stored once per node and deleted when no sync ID references them; a blob fetched under one sync ID is taken under every other held sync ID whose entries name it.
- Ephemeral entries and their tombstones are held in memory only and lost at a restart. Relay-only blobs are never held.
- **Caps** (`caps^.0`, spec/data-model.md §9: `policy` and per-thing `things`, applied to each sync ID the thing owns, local policy) govern only the sync IDs the node keeps unread and count only their entries; a sync ID moving between read and kept unread is counted again. A reader's own sync IDs take nothing from the room others may use.
- **Peer budget**: an entry that gives the node nothing held (it does not open, opens to a commit not judged or known only for a part dropped as invalid, or to records pending, spec/commits.md §4 Records), counts its size against the peer that brought it unless stamped: a stamp vouches only under the node's head write key, otherwise the entry is charged (a reader checks a peer's stamp at arrival and again on each head move, charging a held entry whose stamp stopped verifying to the peer that brought it, or not keeping it when that peer is gone; a stamp it holds is not replaced by one that does not verify). Charged entries count within a bound per peer (local policy); past it such entries are not kept. The charges live in the bringing peer's record (spec/sync-opens.md §3), so they survive a restart. A peer with no record is charged per connection, and the entries it brought that still give nothing held are dropped when that connection closes, to be fetched again where present. A dropped record (a lost record is a first contact) drops the entries charged to it.

## 6. Operations at a store
Each operation names a sync ID S. Writes are signed with the role keys of the receiving store's head; a Delete needs S open on the connection (spec/sync-opens.md §4).

- **Steps** (who issues and registers):
  - Only an admin issues a step, once the rotation commits it registers are logged under S here (spec/permissions.md §3), whatever peers it reaches: when it holds, for some role, an established epoch newer than the one its recorded head registers (spec/permissions.md §3 next-step triggers), a child of its recorded head, recorded in `sync.0` in the step's commit. It MAY also issue a step without a rotation (same role keys, fresh step key) to list readers granted since its parent, key actors in particular. No step is issued or registered under a head this node has not recorded.
  - A node reading S registers at each source that keeps S unread (an open by a store credential, spec/sync-opens.md §4) the recorded steps after that source's head, in order: each only once that source's stream showed it holding the role commits of the thing's actor the step's epochs depend on (the rotations of the epochs it registers and of those they supersede), which the registrar logs stamped under the source's head for it to pull. A remover logs the removal and the new `keys.0` first (spec/permissions.md §3).
  - Any reader holding the recorded path moves a source on an older step, not only an admin; Register needs no secret and no open, and is relayable by any node.
  - A deposit-only step (a new deposit key, no other role newer) waits while the node misses a valid `keys.0` part of the thing's actor that it knows of.
  - No rotation answers a fork: sibling steps stand until a step due for another reason lists past them.
- **Register** (delete key of the parent): taken only for a sync ID the node keeps unread (spec/sync.md §3) and in its sync set; a node reading S refuses every Register of S (code 14), as does a node not syncing S.
  - Accept a genesis step only if its delete key hashes to the sync ID and the node holds no step of S.
  - Accept a step whose `prev` is the head; the head itself again is answered OK and changes nothing.
  - Otherwise refuse anything else (a step with another `prev`, a genesis step while the node holds a step of S, an operation under keys of a step it does not hold) with code 9 and nothing more (other codes: spec/wire.md §11.2). A refused registration never carries the head (a registrar learns it from the stream where S is open, or by Behind items).
  - A step is registered with its claim set when the registrar holds it (it MUST hash to the step's). A step held without its set serves no claims at it.
  - **Storage caps**: a step and its claim set count toward the sync ID's and the store's caps (the claim set until it is dropped, §5). Past them:
    - a genesis step is refused (code 12);
    - a child step is accepted without its claim set (it serves no claims);
    - a child step past them even without its set is accepted at most once per sync ID per a policy interval (local policy, non-zero), else refused (code 12), and never refused for a cap otherwise.
  - **Refused for now** (codes 4, 12): the registrar keeps its open and registers again after a back-off (local policy, bounded), never at once.
  - A restart of S at a registrar (S dropped and synced again) forgets what it registered where.
- **Walk** (a reader opening S at a store source, spec/sync-opens.md §4, and moving it along the path). The one rule: a reader opens S at a source only by a credential of that source's **step**, the newest step it knows the source's path holds, and knows a step there only once it verifies.
  - **Known steps** there: the steps its `sync.0` records (every branch), and the steps that source gave (the head event of its stream, spec/sync-streams.md §4; Behind answers), each verified under its parent (the first of an answer under the named step's delete key; a path from genesis from its genesis step, §2). It keeps the source's step in their record (spec/sync-opens.md §3). A step it cannot verify (a sync ID known by ID alone, spec/sync-inbox.md §2) is tested and asked on, nothing more.
  - **Test**: when spec/sync-opens.md §5 Testing says (this node's own changes and re-marks, never a peer's filter alone), it tests its credentials of the known steps, deepest first across every branch, then the sync key of each sync secret it holds, newest first, each distinct credential once. A step's credential is its sync key when the reader holds its sync secret, else its claim key while it holds the step's claim set, else the static entries it claims as; a step whose claim set it dropped gives no claim. The filter shows only the credentials of the source's step (spec/sync-opens.md §4 Admissible: with no head, those of each sync secret it holds), so the first shown is Hit and opens S. A Hit refused counts as none shown. A source's newly shown credentials are found by its own test (spec/sync-opens.md §4 Admissible: it tests its step's sync proof, which the reader shows).
  - **Behind**: none shown, it asks Behind (below) by a credential of the newest known step it holds one of; the verified answer becomes known there and it tests again. Refused (14) on a step: that step is off the source's path (another admin's branch), and it asks on the nearest earlier known step it holds a credential of, each step once per walk. Answered 13: the source does not keep S; nothing follows (once it keeps S its own test opens it). A test asks Behind at most once per sync ID it covers.
  - **Stranded** there (spec/permissions.md §4): it holds no credential of the newest step known there, or Behind refused the newest step the source gave.
  - **Moving it**: open, it registers the recorded steps after the source's step (Steps) when that step is recorded, and nothing when it is not (a sibling, or a step past its `sync.0`). The source's step is the one its stream's head event names (a Hit names none); while none is named it registers its genesis step there first, at once (a source holding no step takes it before any entry it pulls; one holding a step refuses it and its head event follows). A refused Register changes no view; the next head event does.
  - Each Behind answer moves its asker at most one sync key past the credential it showed (below), so a holder of an old step's credential learns at most the first step under another sync key past it, and asks on only by a credential of that step.
- **Behind** (an Offer item, spec/wire.md §11.2): an open signature by a credential key of the step it names: its sync key, a claim of its claim set, or the signing key of a key actor whose static entry the set lists. Naming no step: a sync key (the newest step bearing it), or a key actor's signing key (the head). A node keeping S unread answers:
  - naming a step on its path other than its head whose credential the key is (a claim or static entry only while it holds the step's claim set): the steps after it on its path, in order, through the first whose sync key is not the named step's (without claim sets);
  - naming none, by a sync key a step of its path other than its head bears: the step after the newest such step;
  - naming none, by a key actor's signing key whose static entry its head's claim set lists: the head's entry box for that entry and the path from genesis, as a Static item's Hit is answered (spec/sync-opens.md §5);
  - a sync ID it does not keep: code 13; anything else code 14, carrying nothing (a node reading S answers every Behind of S so).
  - The Behind answers of one Offer carry at most ⌊`REPLY_BUDGET` / 326⌋ steps in all (spec/wire.md §11.2), a path in a grant included: an item reaching that bound is answered with the steps it reached; reaching it with none, or a grant past it, code 4 (refused for now: asked again after a back-off).
- **Stamp**: a signature under S's write key, domain `"osis v1 stamp"` (spec/crypto.md §2), over (sync ID, blob ID, wrap). A node taking the entry checks it against the write key of its head; stamps already taken stay valid across new steps.
- **Role entries**: an entry deletes are judged by (spec/sync-judgement.md §2: a role commit, a commit carrying a request, or a blob such a commit links) is stamped, or signed as a deposit, under `"osis v1 role entry"` in place of the domain above; a node keeping S unread checks either domain alike, and takes a role entry outside S's and its store's caps (it counts toward neither): a stamped one with no bound of its own, a deposited one within the deposit budget. A reader that holds an entry and is shown it under another valid stamp keeps the lower (as bytes), so two writers stamping it under either domain settle on one.
- **Taking a stamped entry**: a node keeping S unread takes the stamped entries it pulls (spec/sync-streams.md §4) by these rules, each with wrap and stamp.
  - Anyone holding a stamped entry may relay it. A stamp under a superseded write key is refused (code 9): such an entry goes as a deposit (spec/sync-inbox.md §3).
  - Refused: a bad stamp; a blob whose prefix expiry has passed; a blob ID with a tombstone; a blob above `MAX_BLOB` (code 3); an ephemeral blob past S's ephemeral cap (code 12).
  - A stamped entry of a deposited entry's blob ID replaces its wrap and stamp and clears its deposited flag.
  - A stamped entry's wrap and stamp never change while it lives: taking its blob ID again changes nothing and logs no event, as does a deposit of a held blob ID.
- **Relay-only** entry: the blob is not stored. It goes on to S's other holders by the stream (spec/sync-streams.md §4, a Stream with no cursor) and leaves no entry, log event, tombstone or expiry.
  - Refused:
    - without an expiry or with one more than `2 × MAX_DRIFT` ahead (code 1);
    - at or past its expiry (code 7);
    - above `MAX_RELAY_BLOB` (code 3);
    - past S's relay rate (code 4).
  - **Taken once**: every node holding S, reading it or keeping it unread, takes a relay-only blob ID once per sync ID until its expiry, and drops a repeat. It remembers a bounded number of them: past the bound the earliest-expiring is forgotten and its expiry becomes the sync ID's **floor**, at or below which relay-only blobs of that sync ID are dropped.
- **Wraps**:
  - **A node holding the blob's key**: it takes only a wrap opening to that key. An entry a source holds stamped, under any step's write key, under any other wrap counts as lacking at that source (spec/sync-judgement.md §2) for as long as the source holds it; a wrap that does not open at a source gets a fresh encryption there. A wrap opening under no read secret held counts so only until a read secret arrives under which it opens to the blob's key.
  - **A node holding no key**: it keeps its wrap unless one of these holds:
    - the new one opens under a held read secret and its own does not;
    - its own opened to a key the blob refused;
    - neither opens and the new one is stamped and its own is not.
  - At a node holding no key, an entry stamped at a source under a wrap that does not open while the node's own does counts as lacking there; when a new wrap that opens replaces another, entries at the sources that gave the other count as lacking there too.
- **Delete**: taken at a node keeping S unread only on a connection where S is open by a store credential (its head's sync key, a claim or a static entry, spec/sync-opens.md §4), else refused whole (code 8); by the delete key, or of one entry by delete keys of levels: one delete signature per commitment group of the blob's prefix, each verifying under that group's commitment at its level (spec/crypto.md §7; one signature may cover several groups committing to the same key), plus a signature under the head's write key when any level is 3 (thing write secret), else its sync key; any other is refused. An empty group (a `nobody` delta's, or a header list's of a commit listing no level-2 key) is never covered: such a blob goes by the delete key or at its expiry. No Delete is sent between readers (spec/sync-judgement.md §3).
  - Removal leaves a tombstone (§5).
- **Expiry**: at the prefix's `T` every node deletes the entry outright: no tombstone.
- **Caps at a node keeping S unread**: it caps storage per sync ID and the memory of ephemeral entries per sync ID (and in total), counting each entry's, log record's and tombstone's overhead besides its blob.
  - An ephemeral entry past its cap is refused (code 12).
  - At the total cap the sync ID using most gives way: its oldest entries (by their latest log event), deleted with no tombstone; role entries never.
  - It may rate-limit deletes, deposits, registrations and relay-only entries per sync ID (code 4, refused for now); pulled stamped entries are refused for room alone (spec/sync-streams.md §4 Full).
