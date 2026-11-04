# Cryptography
> Summary: The algorithms and key material of suite 1: primitives, signatures, key derivation, per-role epochs and boxes, wraps, hashes, delete keys and algorithm agility.

## 1. Suite 1 primitives
- **Signature**: Ed25519 (RFC 8032) with strict verification: reject non-canonical encodings and small-order points (as ed25519-dalek `verify_strict`).
  - A valid Ed25519 public key is the canonical encoding of a curve point not of small order.
  - Batch and single verification MUST agree.
- **AEAD**: XChaCha20-Poly1305: 32-byte key, 24-byte nonce, 16-byte tag.
- **Hash, KDF, MAC**: BLAKE3. `kdf(purpose, secret, input) = keyed_hash(derive_key("osis v1 " + purpose, secret), input)`; BLAKE3 XOF output where more than 32 bytes are needed.
- **Sealed box**: hybrid KEM X25519 + ML-KEM-768 (FIPS 203).
  - Sender: X25519 ephemeral exchange (reject a non-contributory result) giving `ss_x`, `ct_x` (the ephemeral public key); ML-KEM encapsulation giving `ss_m`, `ct_m`.
  - `K = derive_key("osis v1 hybrid kem", ss_x || ss_m || ct_x || ct_m || pk_x || pk_m)`.
  - The payload is sealed under `AEAD_K` with nonce 0 and the box's AD. Box layout: spec/wire.md §7.
  - Public key `pk_x || pk_m` (spec/wire.md §3). It is valid iff `pk_x` is not of small order and `pk_m` passes the FIPS 203 encapsulation-key check. Nothing is sealed to an invalid one.
- **Randomness**: OS CSPRNG.
- Every hash osis computes itself is BLAKE3.

## 2. Signatures
- Signed input is `domain || digest`: an ASCII domain string, then the 32-byte BLAKE3 digest of the signed canonical bytes. Digests per object: spec/wire.md.
- Domains, one per signed object:
  - `"osis v1 commit"` (input digest: the commit ID)
  - `"osis v1 label register"`
  - `"osis v1 label open"`
  - `"osis v1 upload"` (stamps, spec/sync.md §5)
  - `"osis v1 deposit"`
  - `"osis v1 delete"`
  - `"osis v1 lan announce"` (by a dialable key, spec/sync.md §10)
  - `"osis v1 co-reader open"` (by a dialable key, digest as `"osis v1 label open"`, spec/wire.md §11.2)
- Signers: node keys (commits by the node), recovery keys and link keys (commits signed as that key actor), label role keys (spec/sync.md §5), blinded delete keys (§7).

## 3. Keys per actor kind
- **Notation**: a `kdf` written with two arguments has empty input; a tid as input is its 15 bytes; an Ed25519 key "from" a kdf output is the key with that 32-byte seed (RFC 8032).
- **Role secrets**: 32 random bytes per role (read, write, admin) per epoch (§4).
- **Plain thing** (no non-owner holder): its role secrets derive from its owner's.
  - Role secret = `kdf("thing <role>", owner's <role> secret, tid)`, one per epoch of the owner's role (forks included).
  - It sits at the epoch with n = min(owner's n, 2^62 − 1) that the nonce rule (§4) gives the thing, role and derived secret.
  - **Order n** (§4) of a derived epoch: the owner epoch's order n while the thing is plain, its n once the thing has secrets of its own.
- An **ownerless thing** (spec/permissions.md §1) has no derived secrets: its creation commit rotates all three roles from no epoch.
- **Giving a thing secrets of its own** (spec/permissions.md §3) is a rotation of all three roles from its derived epochs: the history boxes carry the derived secrets, the commit wraps under the derived read epoch, `keys.0` is written.
- A node counts a thing as having **secrets of its own** iff it holds a role commit whose `keys.0` part is valid (spec/permissions.md §5.2) and wrote a keyset in the body the node held (its body since dropped or missing counts). A thing whose only such part turns invalid is plain again (derived secrets), the secrets it learned from that commit kept for reading only (§4).
- **Key actor** (node, recovery key, link key): one 32-byte seed.
  - Signing key from `kdf("sign", seed)`.
  - KEM key pair from `kdf("kem", seed)` read as 96 XOF bytes: the first 64 the ML-KEM-768 keygen seed `d || z` (FIPS 203), the last 32 the X25519 private key. Its X25519 half is also its claim key (spec/sync.md §2).
  - Role secrets `kdf("role <role>", seed)`, all at the fixed epoch (0, 32 zero bytes), the one exception to the nonce rule (§4), never rotated.
  - The creation record commits to the signing public key only.
  - A link key's seed is in the link, a recovery key's in its card. The creation nonce of either is `kdf("creation nonce", seed, "")` (spec/wire.md §3).
- **Other actors**: one KEM key pair per role per epoch, `kdf("kem", role secret)`. The read-role pair's X25519 half is the actor's claim key (spec/sync.md §2).
- **`keys.0`**: a struct holding the current keyset only.
  - Per role a `keyset` (spec/data-model.md §9; `delete_key`: §7; a key actor: one KEM key, no epoch).
  - For an actor other than a key actor, also its **inbox** (label ID, hosts; spec/sync.md §2) and **deposit seed** (32 random bytes, spec/sync.md §2).
  - A role's entry is written by the node that rotates that role (spec/permissions.md §3).
  - An admin writes the inbox and deposit seed; it MAY refresh the deposit seed at any time and MUST write a fresh one in each rotation of the read role it makes.
  - A key actor's `keys.0` is written by its own key. A key actor's keyset is fixed by its seed and never rotates: a key actor changes keys only by being replaced (a new key actor added, the old one removed).
- **Dedup secret** of a thing = `derive_key("osis v1 dedup", creation nonce)`.

## 4. `secrets.0` and epochs
Terms in this section depend on each other; each is defined once, under its bold name.

### Epochs
- **Epoch**: each role secret of an actor has an epoch (n, nonce), independent per role. Each epoch names its suite ID.
- **Nonce rule**: the nonce of role r's secret s of actor A at n is `kdf("epoch", s, A's tid || role byte || le64(n))` (32 bytes; role byte 0 read, 1 write, 2 admin).
  - A secret is the secret of the epoch its (actor, role, n) and the nonce rule name.
  - A box, history box entry or entry box carrying a secret is read as naming that epoch.
- **Rotation** of a set of roles (spec/permissions.md §3): each role gets a fresh random secret under epoch n+1 with the nonce the rule gives; the other roles keep their secret and epoch. n is the greatest n of the role's current epochs at the rotator (epochs it has not established never count; 0 for an actor with no epoch of the role at all, an ownerless thing's creation).
- **Lists**: a rotation's keyset of r (§3) lists each current epoch of r at the rotator other than a derived one (§3) (spec/wire.md §7).
- **Supersedes**: what a rotation of r to epoch e supersedes is read from its rotation commit alone, whatever else the node held when the commit arrived:
  - the epochs below e's n its keyset lists;
  - at a node holding e's secret, the epochs e's history box lists below e's n.
- **Fork**: concurrent rotations of one role create several epochs with one n. Nodes keep all of them.
- A **rotation commit of** an epoch is a role commit writing its keyset in `keys.0` (and its history box).

### Boxes
- **`secrets.0`** = `{ boxes: map<(holder tid, role, epoch), box>, history: map<(role, epoch), history box> }`.
- A rotation of role r writes r's boxes at the new epoch and removes the boxes keyed with role r at r's current epochs (those it holds). Boxes keyed with other roles are untouched.
- A **box** seals one role's secret of one epoch to a holder, AD = (actor tid, holder tid, role, epoch, form fields). Forms (enum):
  - sealed: `{ recipient keyset epoch (none for a key actor), suite ID, sealed box }` to the holder's KEM key for that role (§3);
  - symmetric: `{ epoch of s, wrap under kdf("box", s) }`, s the holder's own secret of that role, used when the writer holds s (a thing's owner; a key actor by its seed holder).
- A holder gets one box per (role, epoch) written to it, keyed (holder, role, epoch): a key actor's sealed to its one KEM key, an actor's sealed to its KEM key for that role or symmetric.
- A box whose secret does not name its key's (role, epoch) is ignored.
- `keys.0` vouches for no secret: a node holding an epoch's secret derives its keyset itself (§3, §7).
- A node holding no current secret of a role a rotation would write does not make that rotation (nor a removal or demotion needing it); it waits for a re-seal, or an admin recovers (spec/permissions.md §3, Lockout recovery).
- A **grant** writes the grantee's boxes for every granted role at each of that role's current epochs.
- A rotation writes new boxes for every current holder of each rotated role, the owner included, with the keysets and history boxes, in one role commit (the **rotation commit**; its boxes page, spec/crdt.md §8).
- A **re-seal** (spec/permissions.md §3) writes a current holder's boxes for the current epochs of the roles it names.
- **Sealer's names for M**: every box to a holder actor M (not a key actor), by a grant, a re-seal or a rotation, carries them (spec/wire.md §7):
  - the names a rotation of M by the sealing node would carry for M and the things below it (Names, below);
  - a keyset name per box (M, its role, the epoch of M it names).
  - A box sealed bound (below) carries none.
- **History box** (role r, epoch e) = AEAD under `kdf("history", secret_r[e])` of:
  - every distinct earlier `secret_r` of an established epoch the rotator holds, forks included;
  - the rotation's names (below).
  - It is written by the rotation of e. A grant or re-seal boxing e writes it again unchanged.
  - A reader tries each live entry of a history key (spec/crdt.md §5.6), not only their merged read, with the secret of e it holds.

### Names
- **Below**: a thing is below A when it is a current holder of A, the owner included, or, transitively, a current holder of such a thing, whether or not it has secrets of its own.
- **Names**: a rotation of actor A names the departures its rotator holds from A and from each thing below A, read from its own role timeline (spec/permissions.md §5.1), never copied from another history box. For each such thing T:
  - T's epoch start at the rotator (a roster snapshot, spec/permissions.md §6), if any;
  - every applied commit ordered after it that applies an edge write on T lowering an edge (a removal, demotion, self-removal or finalize);
  - every applied commit ordered after the start whose demotion's audit dropped (spec/permissions.md §5.1) an edge write on T, named once per thing its edge writes target.
- A name is that thing and the commit's key (spec/permissions.md §6).
- **Keyset name**: per holder actor M it boxes and role r, the rotation also names (M, r, the epoch of M its box names, the symmetric form's epoch of s included).
- **Departs mark**: when the rotation commit itself writes such an edge on A it cannot name itself. The names then carry its departs mark, its `ts` and signing node.
- Every history box of one rotation carries the same names.
- The rotator places every named commit under each label it places the rotation commit under (spec/sync.md §5).
- **Met**: the names of a history box entry are met at a node when all of these hold:
  - each name's commit is applied at the node with its `roles.0` delta on the name's thing held, or, having none there, its `keys.0` delta there (a dropped one counts; a copy of the commit lacking it does not), or its key is ordered before the node's epoch start (spec/permissions.md §6) of the name's thing.
  - each keyset name (M, r, f) is **held**: some valid `keys.0` body of M the node holds (a role commit's delta or a compaction snapshot; a dropped one counts) writes f as M's keyset of r or lists f in that keyset's supersedes (no epoch start stands in).
  - its departs mark, if any, is met: the node holds that commit (by those two) or its epoch start of A is ordered after them.

### Established and current
- **Established**: an epoch e of r is established at a node in either of two cases.
  - It is a key actor's fixed epoch, or derived (§3) from an established epoch of the owner.
  - All of these hold:
    - the node holds a valid rotation commit of e (its own included) or a compaction snapshot of `secrets.0` that keys a box or history box with e;
    - e's n is at most 2^62, or the node holds another established epoch of r with n at least e's n − 1;
    - if the node holds e's secret (other than for reading only), some live entry of e's history box that opens under that secret has its names met.
- A node compacts `secrets.0` only while every epoch its state keys is established.
- **Current**: a role's current epochs are its established epochs that no established rotation superseded.
- **Newest**: a role's newest epoch is the current one with the greatest order n (its n, a derived epoch's per §3), ties by lowest nonce; "newer" compares alike.
- **Uses**: a node uses an epoch (encrypts under it, boxes its secret, puts it in a history box) only when it is established.

### Departures and covering
- **Holders for keys**: the holders of A by the role timeline (spec/permissions.md §5.1) with every applied edge write in effect and `until` disregarded, a removal's value saying keep (`until` 0, spec/permissions.md §2) counting as no edge; the owner holds admin. Keys read no clock: an edge past its `until` stays a holder until its finalize (spec/permissions.md §2). "Current holder" in this section and in spec/permissions.md §3 means a holder for keys.
- **Departure** from role r of actor A: an applied edge write removing a holder M or demoting it below r, as holders for keys see it (a finalize is a removal).
- **Inside**: a departure inside a holder M of A is a departure from M or inside a holder of M (a device of M, a holder on an actor under M, and so on). Chains have no depth bound and may pass an actor more than once, A included (a role cycle, spec/permissions.md §3), but never pass the departed holder.
- **Concerns**: a departure concerns the roles of A the departed party held through the chain: those it left of the last actor, at most each actor's role on the next.
- **Attributes**: a node attributes a departure of holder H from thing T it knows of to the name of the newest (by key; one commit named on two things by the greater thing) of:
  - an applied commit ordered after its epoch start of T whose edge write lowered H's edge on T;
  - an applied commit ordered after that start whose demotion's audit dropped an edge write putting H's edge on T (named on the first of the things its edge writes target).
  - A holder with a box at a current epoch of T whose role it no longer holds and no such commit is attributed to its epoch start of T, or, with none, to nothing.
- **Covers**: an epoch e of role r of A **covers** a departure that concerns r when some live entry of e's history box whose names are met at the node names it: its name is among the names, or it is a departure from A by the rotation commit itself (its departs mark). Boxes decide nothing: an epoch is relied on only for what its rotator held.

### Encrypting under
- **Encrypting under** an epoch means:
  - wrapping under a label read key derived from its secret (§5);
  - sealing or wrapping a box carrying its secret, or a box under its secret or a KEM key derived from it;
  - signing a stamp, step or delete under a label key derived from it.
  - Signing with a delete key (§7), opening a label and reading are not encrypting under.
- A node that may rotate role r of an actor (spec/permissions.md §3) MUST NOT **encrypt under** an epoch of r that does not cover a departure it knows of; it rotates first. Exceptions:
  - The wrap of a rotation commit itself (§5).
  - A departure whose newest edge write is the node's own self-removal (spec/permissions.md §2; signed by it or a key actor it holds) holds back none of the node's encrypting, here or under spec/permissions.md §4, until that commit is placed (spec/sync.md §5, Placed). Both are judged from what the node stores.
- **Established only**: a node encrypts under established epochs only, except under the epochs a rotation commit makes in that commit itself. The secret of any other epoch (one whose rotation commit it has not applied, or is pending or invalid, spec/commits.md §4) is kept for reading.
- **Reading-only secrets**: a secret learned only from a pending or invalid commit (from its boxes, or from history boxes opened with such a secret) is kept for reading and never encrypted under until an applied valid box or a history box opened with a secret not so learned carries it. Such a commit's epochs count for nothing else: a box it holds that the node cannot open records nothing; what its history boxes list supersedes nothing.

### Sealing to a holder actor
- **Keeps out**: an epoch f of role r of a holder actor M keeps out a departure when it holds no box for a departed holder of M, and, for a departure inside a holder M' of M, M's box in f names the newest keyset epoch of M' for r (§3; the symmetric form's epoch of s) that the node holds and that epoch of M' keeps out the rest. This is the box judgement: it only chooses the keyset a box to M names (spec/permissions.md §3).
  - A node that holds no secret of M judges by M's newest `keys.0` keyset it holds alone and by the boxes of M's `secrets.0` it holds. It counts that keyset's epoch as holding a box for a holder that left M unless the keyset was set by the commit that made the departure, or the node holds the `secrets.0` delta of the commit that set it and that delta boxes no such holder.
  - Times decide nothing.
- **Sealers' boxes**: a node seals A's secret to a holder actor M (a rotation, grant or re-seal) for a set of roles only when the names of every box to M of those roles it holds are met at the node; else M is left out (spec/permissions.md §3). Names it cannot open count as unmet. A box of another role does not count. The boxes that count are:
  - every such box in A's `secrets.0` at a current epoch of A;
  - the boxes to M of every held commit putting M's edge on A (the put applied, or the commit ordered before A's epoch start) whose `secrets.0` delta on A is valid and held or dropped.
- **Free**: holding at least one such box, or granting M while M holds no edge on A and the node lacks no such commit's `secrets.0` delta on A, the node seals free, by its box judgement.
- **Bound**: holding none, the node seals bound. M's edge on A (its roster entry, spec/permissions.md §6; M holding none, the newest such commit whose delta it lacks) names in `keyset` (spec/data-model.md §9) the key of a `keys.0` commit of M.
  - The node seals M only to that commit's read keyset, for role read only (M is left out of the roles above), when both hold:
    - it holds the commit applied with its `keys.0` delta on M valid and not missing (dropped: M's `keys.0` keyset of read is the one the delta wrote);
    - for each departure inside M it knows concerning read, that keyset's epoch is M's newest epoch of read at the node and keeps the departure out.
  - Else, or when the edge names none, M is left out.
- **`keyset` of an edge**:
  - An edge write putting M's edge on A that boxes M (a grant or raise) writes in `keyset` the key of the rotation commit of the epoch of M its read box names (sealed bound: the commit it is bound to; holding no such commit, the standing edge's `keyset`).
  - Every other write of M's edge on A carries the standing edge's `keyset`, and so does a roster snapshot's entry for M.
- A grant that would leave a holder actor out of every role it grants is not made.

## 5. Blobs, wraps, inbox blobs
- **Blob encryption**: a fresh random 32-byte key per encryption; nothing encrypts a blob under a caller-chosen key. Framing, padding, AD and blob ID: spec/wire.md §5; spec/sync.md §1.
- **Wrap** (per label, per blob): carries the blob's suite byte, blob key and order under the label read key `kdf("wrap", label read secret)`. Deterministic. Bytes: spec/wire.md §5.
- **Section** (per thing, inside a commit blob): its parts under a fresh random section key used once; the key under `kdf("section", read secret of the thing)` (own or derived, §3; the owner chain it derives through is in the clear beside it) with a fresh random nonce, AD = the commit ID. Bytes: spec/wire.md §4. The epoch is chosen as for a wrap (below, the rotation exception included); a per-label copy's one section goes under the label group's read secret as its wrap does.
- **Order**: 0 for a commit with a purge request or a part on a role-class aspect, `created.0`, `required.0^` or `group.0`, else the commit's `ts` (a header-only blob too). It is read only to order a node's first sync (spec/sync.md §6), and a wrong one changes nothing else.
- A wrap names no epoch: a reader tries the read secrets it holds, newest first.
- **Who wraps under what**:
  - An uploader wraps under the newest current read epoch whose secret it holds (§4).
  - A node holding no current secret places only its stranded heartbeat (spec/permissions.md §4), wrapped under the newest established secret it holds.
  - Exception: a commit carrying boxes of a read epoch e (a rotation) is wrapped, under every label whose read secret derives from that actor's, under the read epoch e supersedes whose secret the rotator holds with the greatest n, ties by lowest nonce (n, not order n, §4). One superseding none (an ownerless thing's creation) is wrapped under e.
- Label role keys for a host are those of the epochs its current step registers (spec/sync.md §5).
- **Inbox blob** (spec/sync.md §3): a role commit (header and deltas) about the recipient, plus the label IDs and host addresses of the things it names, sealed to the recipient actor's read-role KEM key. Bytes: spec/wire.md §9.
  - Its prefix expiry is a delivery lifetime (`INBOX_LIFETIME`), not a commit expiry.
  - It has no blob key and its entry's wrap is filler.

## 6. Hashes and links
- Keyed content hashes, under the dedup secret:
  - delta hash `kdf("delta", dedup secret, delta bytes)`;
  - link content hash of a chunk, page or tree node: spec/wire.md §6;
  - a heartbeat's state digest `kdf("state", dedup secret, ak || 0x00 || state bytes)` cut to 16 bytes (spec/permissions.md §4).
- **Link**: (link content hash 32, blob ID 32, suite byte || blob key 33).

## 7. Delete keys
- **Levels** of a delta, by its retention (spec/commits.md §5), one per member of its set:

  | level | retention set members | secret |
  |---|---|---|
  | 1, admin | `admin`, `author_or_admin`, `writer` | the admin secret of its thing |
  | 2, author | `author`, `author_or_admin`, `writer` | the write secret of the commit's header actor (the author chain; spec/permissions.md §5.2) |
  | 3, writer | `writer` | the write secret of its thing |
  | none | `nobody` | none |

- **Delete base**: a thing or actor without secrets of its own (§3) uses those of its owner, up its owner chain to the first actor with secrets of its own or a key actor (its delete base). An ownerless thing is its own, its creation commit's deltas on it at the epochs that commit makes.
- **Delete key** of a role secret s: the Ed25519 key with seed `kdf("delete key", s)` (secret scalar a, public key A = a·B, RFC 8032).
  - Each keyset in `keys.0` publishes its epoch's (§3).
  - A delete base that is a key actor has its signing key (§3) as delete key at every level.
- **Header list**: a header lists, per level of each delta, the first of these for the base; a writer holding none of them cannot write:
  - the base's delete key of the newest current epoch of that level's secret the writer holds;
  - the `delete_key` of the base's `keys.0` keyset of that role it holds;
  - the one an inbox payload named for the base (spec/wire.md §9), taken only once the carried commit applied valid, touches the base and is by an admin of it, the first kept until the base's `keys.0` arrives.
- Every delta lists exactly the levels its retention calls for (spec/wire.md §4).
- **Commitment** in a blob prefix = level byte || A' = h·A, h = `kdf("delete blind", A, prefix salt || blind)` read as 64 XOF bytes, little-endian, mod ℓ (the order of B).
  - A is taken as its 32-byte encoding.
  - `blind` is the 16 random bytes of the header that lists A, or for a chunk, tree node or page of the header that introduced it.
  - A blob commits to the delete keys of the deltas it serves, in groups, one per distinct delete-key set (spec/wire.md §5).
- **Delete signature** for a blob: Ed25519 (RFC 8032 signing) over `"osis v1 delete" || digest` (§2, spec/wire.md §11.2) with secret scalar h·a mod ℓ, nonce prefix `kdf("delete nonce", seed, prefix salt || blind)` (seed: the delete key's RFC 8032 seed), and public key A'.
  - It verifies strictly under A' (§1).
  - A host checks it against the blob prefix's commitment at its level in a group, one per group for a Delete, and requires the label signature the levels call for (spec/sync.md §5).
- A holder tries every epoch it holds of the level's secret along the delete base's owner chain (a thing that got secrets of its own keeps its earlier content under its former base's keys) and signs with the one whose key the header lists.

## 8. Agility
- Keys, signatures, KEM public keys and sealed boxes are enums (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today. Cases are never removed; a new primitive is a new case.
- AEAD and KDF choices ride on the suite byte of wraps and links and the suite ID of a secret epoch. Suite 1 is the only suite.
- An unknown case or suite parks (spec/versioning.md §2).
- Migrating an actor to a new suite is a new epoch under that suite; old content stays under its suite. A key actor migrates by being replaced (§3).
