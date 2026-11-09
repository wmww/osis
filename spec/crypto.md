# Cryptography
> Summary: The algorithms and key material of suite 1: primitives, signatures, key derivation, per-role epochs and boxes, wraps, hashes, delete keys, algorithm agility and the signing chain.

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
  - `"osis v1 possession"` (a box's possession signature and a keyset's possession proof, spec/wire.md §7)
- Signers: node keys (commits by the node), recovery keys and link keys (commits signed as that key actor), label role keys (spec/sync.md §5), blinded delete keys (§7), possession keys (§4, Holder actors).

## 3. Keys per actor kind
- **Notation**: a `kdf` written with two arguments has empty input; a tid as input is its 15 bytes; an Ed25519 key "from" a kdf output is the key with that 32-byte seed (RFC 8032).
- **Role secrets**: 32 random bytes per role (read, write, admin) per epoch (§4).
- **Plain thing** (spec/permissions.md §3): its role secrets derive from those of the next thing up its record chain (spec/permissions.md §1: its first admin), its **base actor**, and so on up while that one is plain too.
  - Its **derivation chain**: its record chain up to and including the first actor with secrets of its own or a key actor. Only keys use it (derivation, delete keys, section chains, spec/wire.md §4); it carries no authority.
  - Role secret = `kdf("thing <role>", base actor's <role> secret, tid)`, one per epoch of the base actor's role (forks included).
  - It sits at the epoch with n = min(base actor's n, 2^62 − 1) that the nonce rule (§4) gives the thing, role and derived secret.
  - **Order n** (§4) of a derived epoch: the base actor epoch's order n while the thing is plain, its n once the thing has secrets of its own.
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
  - Per role a `keyset` (spec/data-model.md §9; `delete_key`: §7; `possession_key`: §4, Holder actors; a key actor: one KEM key, no epoch).
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
- **Rotation** of a set of roles (spec/permissions.md §3): each role gets a fresh random secret under epoch n+1 with the nonce the rule gives; the other roles keep their secret and epoch. n is the greatest n of the role's current epochs at the rotator (epochs it has not established never count; 0 for an actor with no epoch of the role at all).
- **Lists**: a rotation's keyset of r (§3) lists each current epoch of r at the rotator other than a derived one (§3) (spec/wire.md §7).
- **Supersedes**: what a rotation of r to epoch e supersedes is read from its rotation commit alone, whatever else the node held when the commit arrived:
  - the epochs below e's n its keyset lists;
  - at a node holding e's secret, the epochs e's history box lists below e's n.
- **Fork**: concurrent rotations of one role create several epochs with one n. Nodes keep all of them.
- A **rotation commit of** an epoch is a role commit writing its keyset in `keys.0` (and its history box). The keyset carries the digest of the rotation's names (Names, below; spec/wire.md §7).

### Boxes
- **`secrets.0`** = `{ boxes: map<(holder tid, role, epoch), box>, history: map<(role, epoch), history box> }`.
- A rotation of role r writes r's boxes at the new epoch and removes the boxes keyed with role r at the epochs whose secret its history box carries (below). A box at an epoch it cannot open, or does not hold established, stands: it still opens for its holder, which then adds that secret to the history (History box, below). Boxes keyed with other roles are untouched.
- A **box** seals one role's secret of one epoch to a holder, AD = (actor tid, holder tid, role, epoch, form fields). Forms (enum):
  - sealed: `{ recipient keyset epoch (none for a key actor), suite ID, sealed box }` to the holder's KEM key for that role (§3);
  - symmetric: `{ epoch of s, wrap under kdf("box", s) }`, s the holder's own secret of that role, used when the writer holds s (the first admin a plain thing derived from; a key actor by its seed holder).
- A holder gets one box per (role, epoch) written to it, keyed (holder, role, epoch): a key actor's sealed to its one KEM key, an actor's sealed to its KEM key for that role or symmetric.
- A box whose secret does not name its key's (role, epoch) is ignored.
- An actor's **boxes**, as every rule of this section judges them, are those of its `secrets.0` state; the boxes of a `secrets.0` delta a node judges invalid count for nothing. Such a box still opens for its holder until that role's next rotation, which nothing it does brings about (an admin demoted to reader while granting X read leaves X reading): it carries a secret its author held (a secret once shared cannot be un-shared, spec/requirements.md Permissions), and an author that no longer holds that role has a departure of its own (Departures and covering, below).
- `keys.0` vouches for no secret: a node holding an epoch's secret derives its keyset itself (§3, §7).
- **Rotating needs only the right to rotate** (spec/permissions.md §3), never a secret of the role: a rotation lists and supersedes every current epoch, held or not; its history box carries the established secrets the rotator holds, and a holder of a superseded secret it lacks adds that secret (History box, below). An epoch whose secret a node lacks covers nothing at it (Departures and covering): it rotates. Only the commit's wrap needs a secret (§5): a node holding no established read secret of the actor at all is stranded (spec/permissions.md §4) until re-sealed.
- A **grant** writes the grantee's boxes for every granted role at each of that role's current epochs.
- A rotation writes new boxes for every current holder of each rotated role, with the keysets and history boxes, in one role commit (the **rotation commit**; its boxes page, spec/crdt.md §8).
- A **re-seal** (spec/permissions.md §3) writes a current holder's boxes for the current epochs of the roles it names.
- A holder actor is boxed as Holder actors (below) says, by a grant, a re-seal and a rotation alike.
- **History box** (role r, epoch e) = AEAD under `kdf("history", secret_r[e])` of:
  - every distinct earlier `secret_r` (n below e's) of an established superseded epoch the writer holds, and every one the live entries of the key it opens list (a current epoch's secret travels by box, and a merge supersedes it; so what e supersedes stays what its keyset lists);
  - the rotation's names (below), the same in every entry of the key.
  - It is written by the rotation of e; a grant or re-seal boxing e writes it again, from what its writer holds; where e is blocked at the writer (Encrypting under), only what the live entries list (a history entry is encrypted under e).
  - **History add**: a node holding e's secret, e established and not blocked at it (Encrypting under), that holds such a secret no live entry of the key it opens lists, puts an entry carrying what it holds beside the entries there (resetting none), whatever its role on the actor (a secret once shared cannot be un-shared, spec/requirements.md Permissions), deciding at the end of a complete pass (spec/permissions.md §3). Nothing re-seals a superseded epoch: this is how its content reaches holders that were not boxed at it.
  - A reader tries each live entry of a history key (spec/crdt.md §5.6), not only their merged read, with the secret of e it holds.

### Names
- **Lowering**: a point of A's role timeline (spec/permissions.md §5.1) at which a holder's grant on A for keys (Departures and covering, below) is lowered: an applied edge write on A after which the holder holds less for keys than just before it (a removal, demotion, self-removal or finalize; A's grants for keys are constant between applied edge writes on A), or a demotion elsewhere whose audit dropped (spec/permissions.md §5.1) an edge write on A that had raised the holder (its value above the holder's grant for keys just before its own point): the holder leaves the roles from read up to that value. A dropped write that lowered the holder raised nobody and lowers nobody by going; a renewal lowers nobody.
- **Names**: a rotation of actor A names the lowerings on A its rotator holds, read from its own role timeline, never copied from another history box: an edge write's commit named on A; a demotion elsewhere named once per thing its edge writes target.
- A name is that thing and the commit's key (spec/permissions.md §5.1).
- **Departs mark**: when the rotation commit itself writes such a grant on A it cannot name itself. The names then carry its departs mark, its `ts` and signing node.
- Every history box of one rotation carries the same names, and the rotated roles' keysets carry their digest (spec/wire.md §7): an entry is **bound** to each held valid rotation commit of its epoch whose keyset carries the digest of its names; a held valid `keys.0` compaction snapshot carrying the keyset beside a `secrets.0` snapshot carrying the entry counts as one, by its author.
- The rotator places every named commit under each label it places the rotation commit under (spec/sync.md §5).
- **Met**: the names of a history box entry are met at a node when both hold:
  - each name's commit is applied at the node with its `roles.0` delta on the name's thing held, or, having none there, its `keys.0` delta there (a dropped one counts; a copy of the commit lacking it does not) and resolved (spec/permissions.md §2: every entry its removals reset known, so its edge writes take part in the walk; a finalize held without the write it ends removes nobody).
  - its departs mark, if any, is met: the node holds a role commit by that `ts` and signing node with its `roles.0` delta on A, resolved (as above).
  - A holder of an epoch's secret may put an entry at its history key with any names, bound to nothing: it establishes the epoch where the genuine entry would not (a secret once shared cannot be un-shared) and covers nothing.

### Established and current
- **Established**: an epoch e of r is established at a node in either of two cases.
  - It is a key actor's fixed epoch, or derived (§3) from an established epoch of the base actor.
  - All of these hold:
    - the node holds a valid rotation commit of e (its own included) or a compaction snapshot of `secrets.0` that keys a box or history box with e;
    - e's n is at most 2^62, or the node holds another established epoch of r with n at least e's n − 1;
    - if the node holds e's secret (other than for reading only), some live entry of e's history box that opens under that secret has its names met.
- A node compacts `secrets.0` only while every epoch its state keys is established.
- **Current**: a role's current epochs are its established epochs that no established rotation superseded.
  - Limit: a write under a derived epoch (§3) that no epoch of the thing's own carries in its history (written before its writer held the thing's own epochs) is read only by holders of the base actor's secrets.
- **Newest**: a role's newest epoch is the current one with the greatest order n (its n, a derived epoch's per §3), ties by lowest nonce; "newer" compares alike.
- **Uses**: a node uses an epoch (encrypts under it, boxes its secret, puts it in a history box) only when it is established.

### Departures and covering
- **Holders for keys**: the holders of A by the role timeline (spec/permissions.md §5.1) with every applied edge write in effect and `until` disregarded, a removal's value saying retain (`until` 0, spec/permissions.md §2) counting as no edge; the record edge counts while it stands. Keys read no clock: an edge past its `until` stays a holder until its finalize (spec/permissions.md §2). "Current holder" in this section and in spec/permissions.md §3 means a holder for keys.
- **Departure** from role r of actor A: an applied edge write removing a holder M or demoting it below r, as holders for keys see it (a finalize is a removal). It **concerns** the roles of A that M left. A departure from a holder actor of A, or below one, is none of A's (Holder actors, below).
- **Attributes**: a node attributes a departure of holder H from A it knows of to the name of the newest lowering of H (Names; by key, one commit named on two things by the greater thing). A holder with a box (Boxes) at a current epoch of A whose role it no longer holds and no such lowering is attributed to nothing.
- **Holds**: the author of a commit holds r on A at a node when its effective role on A (spec/permissions.md §1) over the node's applied edge writes, every `until` disregarded and a removal's retain value counting as no edge (Holders for keys), is at least r.
- **Covers**: an epoch e of role r of A **covers** a departure that concerns r when some live entry of e's history box, its names met and bound (Names) to a held valid keyset of e whose body's author holds r on A, names it: its name is among the entry's names, or it is a departure from A attributed to the commit the entry's departs mark names (by `ts` and signing node) and that node holds r on A.
  - Boxes decide nothing: an epoch is relied on only for what its rotator held. What covers a departure is the signed word of a rotator holding the role: the departed party can write entries (bound to nothing), backdate a rotation of its own or rotate in its self-removal, and holds the role in none of them.
  - A rotator holding the role may name a departure it holds while boxing the departed party: a secret once shared cannot be un-shared.

### Encrypting under
- **Encrypting under** an epoch means:
  - wrapping under a label read key derived from its secret (§5);
  - sealing or wrapping a box under its secret or a KEM key derived from it. A box carrying a secret is encrypted under its recipient's key (a holder actor's keyset, Holder actors), not under the epoch it carries;
  - signing a stamp, step or delete under a label key derived from it.
  - Signing with a delete key (§7), opening a label and reading are not encrypting under.
- A node MUST NOT **encrypt under** an epoch e of role r of actor A that is **blocked** at it; one that may rotate r (spec/permissions.md §3) rotates first, another waits for a rotation. e is blocked at a node holding its secret when:
  - e does not cover a departure from A the node knows of;
  - the node may rotate r, and e has a stale box (Holder actors, below), a box to a holder whose grant on A is keyless (Holder actors), or a box to a holder actor M naming an epoch of M blocked at the node (the box's sealing was encrypting under it).
  - Limit: a node does not judge an epoch whose secret it lacks; it seals a holder actor M at such a keyset whatever departures from M it knows, and a party removed from M opens what it so seals until M's knowing keyset reaches it (Holder actors).
  - Exception: the wrap of a rotation commit itself (§5).
  - Exception: a departure whose newest edge write is the node's own self-removal (spec/permissions.md §2; signed by it or a key actor it holds) holds back none of the node's encrypting, here or under spec/permissions.md §4, until that commit is placed (spec/sync.md §5, Placed). Both are judged from what the node stores.
- A node that may rotate r also rotates r before it next encrypts under A while any current epoch of r, not only the newest, does not cover a departure it knows of (one whose secret it lacks covers nothing), or has a stale box (Holder actors) or a box to a holder whose grant on A is keyless (the **knowing re-key**), or r has more than one current epoch and the node is its **merger** (**merge**: a fork made without knowing a departure stays current otherwise, and may be the newest; a holder actor anchored at two forks of its keysets has no keyset to be sealed at).
  - **Merger** of a fork of r: a node that made (signed the rotation commit of) a current epoch of r other than the newest, or, when no maker of one may rotate r, any node that may.
  - A rotation that Seal makes wait (Holder actors) waits; meanwhile the node encrypts under the newest epoch as this section allows.
- **Established only**: a node encrypts under established epochs only, except under the epochs a rotation commit makes in that commit itself. The secret of any other epoch (one whose rotation commit it has not applied, or is pending or invalid, spec/commits.md §4) is kept for reading.
- **Reading-only secrets**: a secret learned only from a pending or invalid commit (from its boxes, or from history boxes opened with such a secret) is kept for reading and never encrypted under until an applied valid box or a history box opened with a secret not so learned carries it. Such a commit's epochs count for nothing else: a box it holds that the node cannot open records nothing; what its history boxes list supersedes nothing.

### Holder actors
A **holder actor** of A is a holder for keys of A (its first admin included while the record edge stands) that is an actor other than a key actor. How a node boxes it depends on its keysets, on actor grants, and on which of its epochs are blocked at the node (Encrypting under); a departure from it or below it is none of A's.
- **Held keyset**: a keyset of role r of actor M is held at a node when the node holds a `keys.0` body of M writing it as r's keyset (a role commit's delta or a compaction snapshot; a dropped one counts). It is valid when some such body is valid (spec/permissions.md §5.2), held invalid when each such body is invalid.
- **Descends**: a held valid keyset k descends from epoch j when k's supersedes list names j, or names a held valid keyset that descends from j. A held invalid keyset passes nothing on (a forged keyset lists every keyset).
- **Key access** (no key cycles):
  - An **actor grant** on A is a holder actor H's standing on A: its grant; a first admin's record edge is a standing since A's creation, ordered before every write (its key yields A's from A's creation, so it is never the one left keyless).
  - Actor grants are ordered by the key (spec/permissions.md §5.1) of the write that started H's present standing on A: the earliest applied edge write since which H has held a role on A for keys without a break. One standing since A's creation (a record edge) is ordered before every write. Ties go by A's tid, then H's.
  - An actor edge whose removal the node holds applied is no standing: key access is judged over the actor grants held less those, so a removal can give a later grant key access (re-sealed, spec/permissions.md §3).
  - A node takes the actor grants it holds in that order and gives each **key access** unless A's key already yields H's over the grants given key access before it (the grant would close a cycle): X's key **yields** Y's when X holds such a grant on Y, or on an actor whose key yields Y's. Such a grant is **keyless**: the earlier grant wins, the later reads nothing.
  - A rotation, grant or re-seal of A boxes no actor without key access to A. A keyless grant is a role all the same (spec/permissions.md §5).
- **Tainted**: a keyset k of role r of actor M is tainted at a node when M's boxes include one at epoch k to a holder whose actor grant on M is keyless (a box to a departed holder is a departure from M, not a taint).
- **Anchors** of holder actor M for role r of A: the held valid keysets of M that the boxes to M of role r at A's current epochs name (a sealed box's recipient keyset epoch, a symmetric box's epoch of s).
- **Seal**: a rotation, grant or re-seal of A boxes holder actor M with key access, for role r, at the newest (greatest n, ties by lowest nonce) held valid keyset of role r of M that is not tainted and is or descends from each anchor: symmetric when the node holds that epoch's secret, else sealed to its KEM key. When that epoch is blocked at the node, M is left out of r and the roles above, and re-sealed (spec/permissions.md §3) once it is not. With none:
  - when no held valid keyset of M, tainted or not, is or descends from each anchor (the anchors fork), the node makes no rotation, grant or re-seal of A boxing M until one is (M's merge, §4 Encrypting under); a removal needing that rotation goes without it (spec/permissions.md §3). Limit: while M's merger does not act (a lost node still holding its role on M, or a writer of M withholding its merge), A's rotation waits, and with it every encrypting under A that a departure or stale box holds back, and A's holders read nothing new of what A holds a role on that a node knowing such a departure rotates (A is left out of it); removing the merger from M, or M from A, ends that;
  - otherwise M is left out of r and the roles above, and re-sealed (spec/permissions.md §3) once one exists.
- **Stale**: a box of A to holder actor M naming epoch k of M is stale at a node when k is held invalid, tainted, or named by the supersedes list of a held valid keyset of M. A keyset the node holds no body of and finds in no such list is not stale. Every box to M at an epoch e of A is stale as well when the rotation commit of e carries a proof for M (Possession) naming such a keyset.
- **Carried**: a rotation, grant or re-seal of A places with its commit, under A's labels, the held rotation commits of the keysets its boxes to holder actors name, as certificates (spec/permissions.md §4), so that A's writers can judge those keysets. A certificate of a rotation (its `keys.0` delta) carries its proofs, so a node holding it alone judges its Authority as a node holding the whole commit does.
  - Limit: a node may hold A's box naming M's keyset k without k's body (the box's commit arrived, the carried one not yet). k is then no anchor, and its next rotation of A seals M at the older keyset it holds, which a party removed from M may open; a node holding k finds that box stale and rotates (within the stated limit: that node held no knowing keyset of M).
- Limit: a keyset of M written without knowledge of a removal from M (a concurrent rotation of M, or one the removed party forged, where the removal or the forgery has not arrived) is sealed to as any other: the removed party opens A's epochs so sealed, written since the removal, until A is sealed at a keyset of M descending from a rotation of M that knows.
- Limit: a node that has not seen the earlier grant of a cycle gives the later one key access and may seal into the cycle; a party removed from an actor on it may open the other actors' epochs so sealed until a writer holding every grant of the cycle and its keysets has rotated them.
- **Possession key** of a role secret s: the Ed25519 key with seed `kdf("possession key", s)`. Each keyset in `keys.0` publishes its epoch's (`possession_key`).
- **Possession**: let X be the author of a role commit with a `secrets.0` or `keys.0` delta on A.
  - X's roles here are just before the commit's key (spec/permissions.md §5.1); its role on a holder actor of A counts paths not through A (through A is a cycle, read through a keyless grant).
  - So are keysets: a held valid keyset counts here only by a valid body ordered before the commit's key, and a possession key only as such a body publishes it.
  - A rotation of A (the commit's `keys.0` delta on A writes a keyset) **shows** holder actor M when a keyset it writes carries a proof for M (spec/wire.md §7) that names keyset k of M and verifies under the possession key of k, as a held valid keyset of M publishes it. The rotation boxes M at the keyset its proof names.
  - Another `secrets.0` delta shows M by a box to M that is symmetric at keyset k of M and carries a valid possession signature, by the possession key of k as above.
  - A proof or box naming a keyset the node holds no valid body of (as above) shows M at that node until one arrives (nor is the box stale).
  - **Authority**: when the commit rotates A, its `secrets.0` delta on A writes more than entries, or that delta removes a box of role r to a holder actor X holds r or above on without putting that box again showing it, X must not hold the role needed on A (for a rotation, the right to rotate its rotated roles, spec/permissions.md §3; otherwise what the `secrets.0` delta needs, spec/permissions.md §5.2) only through holder actors of A that the node holds a keyset of and the commit does not show. A rotation failing it is invalid whole: its `keys.0` and `secrets.0` deltas on A, so its keysets are held invalid and its epochs established nowhere; another delta failing it is invalid. A node holding a rotation's `secrets.0` delta but never its `keys.0` delta judges it showing nothing. Nothing else judges a box: one that neither rotates nor removes is valid whether or not it shows its holder.
  - **Writers**: a node makes a rotation only where Authority holds; otherwise it waits (encrypting under A as §4 allows, so not under an epoch with a stale box) until it holds the secret of the keyset Seal gives or no longer holds the role through M; a removal or finalize needing that rotation goes alone (spec/permissions.md §3). A box that cannot show M is sealed to k's KEM key as Seal says.

## 5. Blobs, wraps, inbox blobs
- **Blob encryption**: a fresh random 32-byte key per encryption; nothing encrypts a blob under a caller-chosen key. Framing, padding, AD and blob ID: spec/wire.md §5; spec/sync.md §1.
- **Wrap** (per label, per blob): carries the blob's suite byte, blob key and order under the label read key `kdf("wrap", label read secret)`. Deterministic. Bytes: spec/wire.md §5.
- **Section** (per thing, inside a commit blob): its parts under a fresh random section key used once; the key under `kdf("section", read secret of the thing)` (own or derived, §3; the record chain it derives through is in the clear beside it) with a fresh random nonce, AD = the commit ID. Bytes: spec/wire.md §4. The epoch is chosen as for a wrap (below, the rotation exception included); a per-label copy's one section goes under the label group's read secret as its wrap does.
- **Order**: 0 for a commit with a purge request or a part on a role-class aspect, `created.0`, `required^.0` or `group.0`, else the commit's `ts` (a header-only blob too). It is read only to order a node's first sync (spec/sync.md §6), and a wrong one changes nothing else.
- A wrap names no epoch: a reader tries the read secrets it holds, newest first.
- **Who wraps under what**:
  - An uploader wraps under the newest current read epoch whose secret it holds (§4).
  - A node holding no current secret places only its stranded heartbeat (spec/permissions.md §4), wrapped under the newest established secret it holds.
  - Exception: a commit carrying boxes of a read epoch e (a rotation) is wrapped, under every label whose read secret derives from that actor's, under the read epoch e supersedes whose secret the rotator holds with the greatest n, ties by lowest nonce (n, not order n, §4).
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

- **Delete base**: a thing or actor without secrets of its own (§3) uses those of the last actor of its derivation chain (§3), its delete base.
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
- A holder tries every epoch it holds of the level's secret up the thing's record chain (a thing that got secrets of its own keeps its earlier content under its former base's keys) and signs with the one whose key the header lists.

## 8. Agility
- Keys, signatures, KEM public keys and sealed boxes are enums (`signing_key`, `signature`, `kem_key`, `sealed`) with one case today. Cases are never removed; a new primitive is a new case.
- AEAD and KDF choices ride on the suite byte of wraps and links and the suite ID of a secret epoch. Suite 1 is the only suite.
- An unknown case or suite parks (spec/versioning.md §2).
- Migrating an actor to a new suite is a new epoch under that suite; old content stays under its suite. A key actor migrates by being replaced (§3).

## 9. Signing chain
An account's commits are signed with the key of one of its signing epochs (spec/permissions.md §5.4 judges them). The chain is a DAG of rotations.
- The **first epoch** is fixed by the account's tid. Every other epoch is minted by one rotation and named by that rotation's commit ID.
- A **rotation** carries: the epoch it is **signed at** (the one it rotates, whose key signs it); the epochs it **supersedes** (that one, and for a merge the fork epochs it ends); the fork rotations it **names** (a merge accepts them); and, per named fork, a signature by the key of the epoch that fork mints, over the rotation's commit ID.
- A named fork is **accepted** iff it is held and its signature verifies. A name without its signature accepts nothing.
- A rotation's **parents** are the held rotation minting the epoch it is signed at and the forks it accepts. Its **line** is itself and every held rotation reachable over parents. Epoch e **descends from** rotation r iff r is on the line of e's minting rotation; the first epoch descends from none.
- A rotation is **signed at** the epoch it rotates and at the epoch of each fork it accepts.
