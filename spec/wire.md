# Wire formats
> Summary: Byte layouts of everything that leaves a node, and the table of every constant's value.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a label ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin. A purgeable-by class: 0 `nobody`, 1 `admin`, 2 `author_or_admin`, 3 `writer`, 4 `author`. A delete level: 1, 2, 3 (spec/crypto.md §7).
- An epoch in a structure is `[n, nonce]` (uint, 32-byte byte string; spec/crypto.md §4).
- **AD tuples**: an AEAD associated-data tuple `(a, b, ...)` written in spec/crypto.md is the canonical CBOR array of its items in the encodings of this section; layouts below give each one.
- Signed digests: a signature's digest (spec/crypto.md §2) is BLAKE3 of the canonical bytes of the array the layout names.
- Ed25519 keys and signatures in structures are raw (32 and 64 bytes) where a layout says `pk` or `sig`; where it says `signing_key` or `signature` it holds the agility enum value (§3).

## 2. Constants
### Fixed by the format version
Format version 1, spec/versioning.md §1:

| constant | value |
|---|---|
| format version | 1 |
| `MAX_BLOB` | 8 MiB (8 388 608 bytes), whole blob (prefix and ciphertext) |
| `CHUNK_THRESHOLD` | 128 KiB (131 072 bytes) |
| `MAX_LIST_BYTES` | 64 MiB (67 108 864 bytes), one linked header list's canonical encoding (§4) |
| `PAGE_TARGET` | 64 KiB (65 536 bytes) |
| chunker | `CHUNK_MIN` 16 KiB, `CHUNK_MAX` 256 KiB, gear table and boundary rule §6 |
| tree fan-out | at most 512 links per interior node or link page (§6) |
| `MAX_CLAIMS` | 65 536 keys per claim set |
| `MAX_DELTA_BARE` | 262 144 (2^18) sequence elements in runs without `Content` per writer's delta, pages included (spec/crdt.md §3.3) |
| `MAX_PAGE_ITEMS` | 2 097 152 (2^21) items (CBOR heads plus text string content bytes) in a durable delta's root fragment or one of its pages (spec/crdt.md §8) |
| `MAX_RUN` | 4096 (2^12) elements per sequence run (spec/crdt.md §3.3) |
| `MAX_AK_BYTES` | 1024 bytes, one AK (§4, §13) |
| `MAX_VALUE_DEPTH` | 64 levels of nesting in a value (§13, spec/data-model.md §5) |
| `MAX_DRIFT` | 1 hour |
| `MAX_RELAY_BLOB` | 64 KiB (65 536 bytes), whole relay-only blob (spec/sync.md §5, §9) |
| `ROLE_KEEP` | 90 days |
| `INBOX_LIFETIME` | 90 days |
| `INBOX_WAITING`, `INBOX_WAITING_BYTES` | 32 entries, 1 MiB (1 048 576 bytes): deposits a node leaves at an inbox it clears (spec/sync.md §5) |
| `HEARTBEAT_MIN_LIFETIME`, `HEARTBEAT_MAX_LIFETIME`, `HEARTBEAT_MIN_INTERVAL` | 1 day, 14 days, 6 hours |
| `MAX_HEARTBEAT_SUSPECTS` | 32 |
| `MAX_CHAIN_DEPTH` | 64 links from a thing up its record chain to its key actor (spec/permissions.md §1) |
| `MAX_REQUIRED_ENTRIES` | 64 entries of one `required.0^` delta (spec/commits.md §5) |
| `MAX_AUTHOR_ITEMS` | 32 items by author in one commit's `purge` (§4) |

### Protocol version 1 limits
Not format constants (§11). Per-message caps: §11.2.

| constant | value |
|---|---|
| `MAX_MESSAGE` | 9 MiB (9 437 184 bytes), one frame's `len` (§11.1) |
| `REPLY_BUDGET` | `MAX_MESSAGE` − 64 KiB: the greatest `max_reply` (§11.2) and the bound on a peer's untaken bytes for a push (spec/sync.md §6) |
| `SMALL_REPLY` | 16 KiB (16 384 bytes): the smallest `max_reply` (§11.2) and the reply allowance of every kind without its own (spec/sync.md §6) |
| `WINDOW` | 16 MiB (16 777 216 bytes) a requester keeps in flight per connection (spec/sync.md §6) |
| `MAX_SUBS` | 4096 live subscriptions per connection, counted apart from open labels (§11.2) |
| `MAX_CONNS_PER_CLIENT` | 8 authenticated sessions of one client actor (§11.2) |

### Host and node policy
Not format constants. A value marked recommended is advice.

| name | value |
|---|---|
| `TOMBSTONE_LIFETIME` | recommended 30 days (spec/sync.md §4, §5) |
| deposit budget | recommended minimum `64 + 4 ×` (size of the current step's claim set) entries and that many × 32 KiB bytes (spec/sync.md §5) |
| `MAX_DELIVERED` | 2^16 delivered relay-only commit IDs remembered (spec/sync.md §9) |
| `LOST_HEARD_WAIT_MS` | `ROLE_KEEP`: how long after a node first found a role gone by an `until` alone it drops anyway (spec/permissions.md §2) |
| `PENDING_GRANT_WAIT_MS` | local policy, 1 day: how old a held pending commit boxing a node may be and still count as no loss of access (spec/permissions.md §3) |
| `SETTLE_MS` | local policy, 30 s: how long a node leaves another node's fresh demotion or `keys.0` to its author before copying it (spec/permissions.md §2, §4) |

## 3. Creation records and agility enums
- Agility enums (spec/crypto.md §8) are values: `signing_key = enum { 1 ed25519(blob) }` (32 bytes), `signature = enum { 1 ed25519(blob) }` (64 bytes), `kem_key = enum { 1 x25519_mlkem768(blob) }` (`pk_x || pk_m`, 1216 bytes), `sealed = enum { 1 x25519_mlkem768(blob) }` (`ct_x || ct_m || AEAD`). Each encodes as `1617([1, h'...'])`.
- A **creation record** is the value `creation = struct { 0 admin: tid, 1 key: signing_key, 2 nonce: blob }` holding exactly one of fields 0 and 1, and a 32-byte nonce: a thing `{0: admin, 2: nonce}` (its first admin, spec/permissions.md §1), a key actor `{1: key, 2: nonce}`. Its canonical encoding is what the tid hashes: tid = first 15 bytes of BLAKE3(canonical bytes). `created.0` holds this value (spec/data-model.md §9); a `created.0` whose read does not hash to its tid, holds not exactly one of fields 0 and 1, or any field other than 0 to 2, is bad input (a closed struct, not parked); an unknown `signing_key` case parks the thing (spec/versioning.md §2).
- A link key's or recovery key's nonce is `kdf("creation nonce", seed, "")`; a node's is random.

## 4. Commits
```
Header    := [version, author, actor, kind, ts, form, expires, aspects, chunks,
              purge, undoes, blind, keys, frontier, ephemeral]
Aspect    := [tid, ak, lo, hi, Retention, keys, hash]
Retention := [by, at_least, at_most]
Bound     := {? 0: abs, ? 1: rel}
DeleteKey := [level, pk]
Chunk     := [blob_id, [ki*]]
PurgeItem := [commit_id, tid, ak] | [tid, ak] | [tid, ak, actor]
CommitBlobPlaintext := [Header, signature, [Section*]]
Section   := [[ai*], [chain*], wrap, ciphertext]
Part      := [ai, delta, [creation*]]
```
Header fields by position:
0. `version`: uint, the format version (1).
1. `author`: tid of the signing key actor. 2. `actor`: tid of the actor it acts for (spec/permissions.md §5.2); in a role commit (`kind` 1) equal to `author`, else bad input.
3. `kind`: 0 content, 1 role, 2 content compaction snapshot, 3 role compaction snapshot (spec/commits.md §2).
4. `ts` (spec/crdt.md §2.2). 5. `form`: 0 commit form, or `[1, nonce]` session form with the session's 16-byte nonce (spec/commits.md §3).
6. `expires`: `Opt(T)`, the commit's expiry, wall ms (spec/commits.md §6).
7. `aspects`: `[Aspect+]` sorted by the canonical bytes of `[tid, ak]`, distinct.
8. `chunks`: `[Chunk*]` sorted by blob ID, distinct: every chunk, tree-node and page blob the deltas introduce; `ki` are indices into `keys`, ascending: the delete keys of the delta that created the blob.
9. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[commit_id, tid, ak]` names that commit's deltas on that aspect; `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`; `[tid, ak, actor]` those of them whose commit's purge actor is `actor` (spec/permissions.md §6: the actor its header names). The second place tells the three-item forms apart: a tid, or an AK's text.
10. `undoes`: `Opt(commit_id)`.
11. `blind`: 16 random bytes (spec/crypto.md §7).
12. `keys`: `[DeleteKey*]` sorted by canonical bytes, distinct: the delete keys of the commit's deltas (spec/crypto.md §7), `pk` a valid Ed25519 key (§1, spec/crypto.md §1), at most one at level 2 (the author chain); a key no aspect lists is bad input.
13. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9); present iff the commit is a role commit carrying an explicit demotion (spec/permissions.md §5; a writer rule: a receiver checks only that it sits on a role commit). A value that does not decode as a `frontier` is bad input.
14. `ephemeral`: `Opt(uint)`, the ephemeral marker (spec/commits.md §2): 0 an ephemeral commit, 1 a relay-only one. Present only with `kind` 2 and `form` 0, or `kind` 0 and session form, no `chunks`, no `purge`, no `undoes`, no list by link and no `created.0` aspect; every aspect's retention is `writer` with no bounds, with the levels it calls for; a relay-only commit has no `expires`. Anything else is bad input.

Aspect fields: `tid`; `ak` (text, spec/data-model.md §2, at most `MAX_AK_BYTES`); `lo`, `hi`: the counter range (`lo = hi = 0` for kinds 2, 3; else `1 <= lo < hi`); `Retention`: `by` (purgeable-by class), `at_least` and `at_most` bounds, each a map with optional `0: abs` (wall ms; `2^63 - 1` means forever) and `1: rel` (ms after the body is replaced; in `at_most` only 0), `{}` for no bound; `keys`: `[ki*]`, ascending indices into the header's `keys`: one per level the retention calls for (spec/crypto.md §7), exactly those levels, else bad input; `hash`: the 32-byte delta hash of its one delta.

- **Inline or link**: `aspects`, `chunks`, `purge`, `keys` and the frontier are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the dedup secret of the header's `actor`. A decoder rejects an inline list above the threshold or a link to one at or below it or above `MAX_LIST_BYTES`; a writer refuses such a commit. A linked frontier's encoding is exactly `{0: set<32-byte commit ID>}`; anything else is bad input. Header-list chunks carry the commitments of §5.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the author's key under `"osis v1 commit" || commit ID`.
- **Commit blob** plaintext: `CommitBlobPlaintext`: one blob carries the whole commit, every part sealed to its thing's readers (spec/sync.md §3).
  - A `Section` holds the parts of one thing: `[ai*]` the aspect indices of its parts, ascending, distinct, each with a part inside; `[chain*]` the thing's derivation chain (spec/crypto.md §3) as the writer knows it, nearest first (empty for an actor with secrets of its own or a key actor; at most `MAX_CHAIN_DEPTH`, no tid twice: else bad input); `ciphertext` = XChaCha20-Poly1305 of the canonical `[Part*]` list under a fresh random 32-byte section key, nonce 24 zero bytes (the key encrypts this one plaintext and nothing else), AD = the commit ID; `wrap` = a random 24-byte nonce `||` XChaCha20-Poly1305 of the section key under `kdf("section", read secret of the thing)` (its own, or derived from its base actor's by tid, spec/crypto.md §3) at the newest epoch the writer holds (a rotation's section under the epoch it supersedes, spec/crypto.md §5), that nonce, AD = the commit ID: 72 bytes. Sections sorted by their first `ai`; an aspect in two sections is bad input; zero sections is allowed (every delta purged). A per-label copy (spec/sync.md §3) is one section of its parts, with an empty chain, under the read secret of the label's group.
  - A reader tries, per section, the read secrets it holds of the section's thing, those derived by tid through the listed chain from the epochs it holds of any member of it (the thing's record may be inside the section; a member given secrets of its own since holds the derived epoch in its history), and the read secret of the group of the label the blob came under, newest first. Parts that open on an aspect the section does not list, or a listed aspect with no part, are bad input. A section no held secret opens is kept as it is: a non-reader learns nothing of it beyond its size, `ai` list and chain, and copies it verbatim into a fresh encryption of the commit.
  - A `Part` holds one delta: `ai` indexes `aspects`, `delta` is the embedded `Delta` or `Snapshot` array (spec/crdt.md §3.2, §8) whose canonical bytes hash to that aspect's `hash`, then the creation records (§3) carried beside it (spec/commits.md §2), sorted by tid, distinct; empty in a commit without the ephemeral marker, else bad input. Records are outside the header and delta hash: each hashes to its tid. Within a section parts sorted by `ai`, distinct.
  - The blob's prefix commitment groups are those of the delete keys its sections' aspects list (§5); its expiry is the header's `expires`. The whole commit stays within `MAX_BLOB` (a writer pages its deltas, spec/crdt.md §8, and refuses a commit that still does not fit).
- A header violating a rule of spec/commits.md §2, §5 or §6 is bad input:
  - an aspect of the wrong class for its kind (`created.0` fits either kind);
  - `created.0` in a kind without own writes or with the ephemeral marker;
  - a role compaction snapshot of `roles.0`;
  - a role-class, `created.0`, `required.0^` or `purge.0` aspect whose retention is not its fixed one (spec/commits.md §5);
  - `expires` on a commit with such an aspect;
  - a `nobody` aspect beside an aspect of another purgeable-by, `created.0` and `required.0^` aside (spec/commits.md §5);
  - a content compaction snapshot's retention `by` other than writer;
  - a relative keep at most other than 0, or under a class other than writer;
  - `expires` or a purge item on a role commit;
  - `expires` on a commit with a purge request (spec/commits.md §5);
  - a purge item naming a role-class aspect;
  - more than `MAX_AUTHOR_ITEMS` purge items by author;
  - a frontier outside a role commit (kind 1).

## 5. Blob framing
A blob is `prefix || ciphertext`, at most `MAX_BLOB` bytes. The prefix is a fixed byte layout:

| offset | size | field |
|---|---|---|
| 0 | 1 | framing version: 1 |
| 1 | 16 | salt, random per encryption |
| 17 | 8 | expiry `T`: le64 wall ms; 0 means none |
| 25 | 1 | class: 0 durable, 1 ephemeral, 2 relay-only (spec/sync.md §1); any other value is bad input |
| 26 | 2 | n: number of commitment groups, le16 |
| 28 | … | n groups, each: a count byte m (0..3) then 33·m commitments: level byte (1..3) `||` 32-byte blinded delete key (spec/crypto.md §7), levels strictly ascending within a group |

- The ciphertext runs from the end of the groups to the end of the blob: XChaCha20-Poly1305 under the blob key, nonce 24 zero bytes, AD = the prefix bytes, plaintext = the padded plaintext. **Blob ID** = BLAKE3(whole blob).
- **Padding** (Padmé; Nikitin et al., PURBs): for a plaintext P, let `L = len(P) + 1`, `E = floor(log2 L)`; if `E = 0`, `padme(L) = L`; else with `S` the bit length of `E` and `m = 2^(E - S) - 1`, `padme(L) = (L + m) & ~m`. The padded plaintext is `P || 0x80 || 0x00^(padme(L) - L)`. To unpad: strip trailing `0x00` bytes, then one `0x80`, which MUST be present; the padded length MUST equal `padme(len(P) + 1)`. Anything else is bad input.
- Plaintext per blob kind: commit blob `CommitBlobPlaintext` (§4); chunk: the raw chunk bytes; tree node and link page: §6; page: §6; inbox blob: §9 (its ciphertext is a sealed box, not the AEAD above).
- Class: a commit blob's class is that of its header's ephemeral marker (none: durable, 0: ephemeral, 1: relay-only); a mismatch is bad input. Chunks, tree nodes, pages and inbox blobs are durable. A relay-only commit blob's expiry `T` is its header's `ts` (wall ms) plus `MAX_DRIFT` (its header carries no `expires`); any other is bad input.
- Commitments, blinded by the blob's own salt and the blind of the header listing it (for a chunk, tree node or page: of the header that introduced it), one per level within a group (spec/crypto.md §7):
  - a commit blob carries one group per distinct delete-key set among the aspects its sections list (opened or not), each group the keys of that set in header key order, groups in order of their first aspect; a `nobody` aspect's set is empty, so its group is (a Delete by level then never verifies, spec/sync.md §5); a header-only blob carries no group;
  - a chunk, tree node or page carries one group: the delete keys of the delta that created it;
  - a chunk or tree node of a linked header list (§4) carries one group holding the commitment of the commit's level-2 key only; its expiry is the commit's `expires`.
- **Wrap**: XChaCha20-Poly1305 under `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, empty AD, plaintext `suite (1) || blob key (32) || order (8, little-endian)`: 57 bytes. A filler is 57 random bytes.
- A node that does not know a blob's framing version stores and relays it as a durable blob with no expiry and no commitments.

## 6. Chunker, chunk trees, pages
- **Gear table**: `G[i]` (i = 0..255) is the little-endian u64 at bytes `8i..8i+8` of the 2048-byte BLAKE3 XOF output of the ASCII string `"osis v1 gear table"` (unkeyed).
- **Chunker** over a byte sequence: at each chunk start `h = 0`; for each byte b, `h = (h << 1) + G[b]` (mod 2^64), and the chunk ends after that byte if its length is at least `CHUNK_MIN` and `h >> 48 = 0`, or its length is `CHUNK_MAX`. The last chunk ends at the end of the sequence.
- **Chunk tree** of a large atomic value (spec/data-model.md §6) or a linked header list or frontier (§4): the leaves are the chunks of its canonical bytes. Level 1 groups the leaf links in order into nodes; a node closes after a link when it holds at least 2 links and the link's content hash begins with byte `0x00`, or when it holds 512 links; the last node closes at the end. If a level yields one node, that node is the root; else the links to its nodes are grouped the same way into level + 1. The root is always an interior node, even over one chunk.
- A tree node's plaintext is `[level, [LINK+], [len+]]`: level 1 nodes link chunks, level k nodes link level k−1 nodes. Levels are at most 48. `len` (uint) has one entry per link, in link order: the byte length of the plaintext under that link (a chunk's length at level 1, the sum of a child node's lengths above). A node whose lengths overflow u64, or a level-k node with a length above `512^(k−1) · CHUNK_MAX` (at level 1: a chunk above `CHUNK_MAX`), is bad input.
- **Link content hash** (spec/crypto.md §6), keyed by the dedup secret: of a chunk, `kdf("link", d, chunk bytes)`; of a page or link page, `kdf("link", d, plaintext)`; of a tree node, `kdf("link tree", d, le64(level) || for each link in order: its content hash || le64(its len))`. The root's content hash identifies the value. A reader verifies the content hash of every link it resolves; a mismatch is bad input.
- **Lengths** are the writer's claims: a reader checks every one it resolves a link through (a child node's lengths sum to its length in the parent, a chunk is exactly its length) and treats a mismatch as bad input; it never sizes a buffer from a stated length. A reader may pass a subtree by its length without fetching it (a seek fetches the root and the nodes on the path to the target chunk).
- **Tree reader bounds**: a chunk other than the last that is empty or shorter than `CHUNK_MIN` is bad input. A reader accepting at most `max_len` bytes of a value visits at most `max_len / CHUNK_MIN + 1` chunks, and a tree needing more is too large.
- **Pages** (spec/crdt.md §8): the gear hash runs over the concatenated canonical encodings of the array's elements (of a field map: each field's key then value), `h = 0` at each page start and never reset inside a page; a page closes after the first element at one of whose bytes the page length is at least `CHUNK_MIN` with `h >> 48 = 0`, or at whose end the page holds `CHUNK_MAX` bytes or more; the last page closes at the end of the array. A page's plaintext is the canonical array of its elements (of a field map: the canonical map of its fields). If the resulting `[LINK+]` would exceed `PAGE_TARGET` bytes, its links are grouped into link pages by the tree-node rule (level 1 only), each a blob with plaintext `[LINK+]`, and the fragment holds the links to the link pages. A fragment needing a third level cannot be written.

## 7. Boxes
- A sealed box (spec/crypto.md §1) is `ct_x (32) || ct_m (1088) || AEAD_K(nonce 24 zero bytes, AD, payload)`, held in a `sealed` value (§3).
- **`secrets.0` box** (spec/crypto.md §4), a `box` value (spec/data-model.md §9) keyed by `box_key`. AD = `[actor, holder, role, n, nonce, form]` with the key's epoch `[n, nonce]` and `form` = `[0, Opt([kn, knonce]), suite]` for the sealed form (the recipient keyset epoch, none for a key actor) or `[1, [sn, snonce]]` for the symmetric form (the epoch of s).
  - Sealed payload: `[role, n, secret]`, secret 32 bytes, naming the epoch (n, nonce of the secret under the actor's tid and the role, spec/crypto.md §4); a `secrets.0` box's names its key's (role, epoch).
  - Symmetric `wrap`: XChaCha20-Poly1305 under `kdf("box", s)`, nonce = first 24 bytes of BLAKE3(AD), plaintext `suite (1) || secret (32)`: 49 bytes.
  - Symmetric `possession`: present iff the holder is not a key actor: a `signature` by the possession key of s (spec/crypto.md §4, Holder actors) under `"osis v1 possession"`, digest BLAKE3(canonical `[actor, holder, role, n, nonce, form, wrap]`), the AD's items then the wrap.
- **Entry box** (spec/sync.md §2): a `box` value in the sealed form with no keyset epoch, AD = `[label_id, step_key, form]`, payload `[role, n, secret, earlier]` with the read role, `earlier` `[n, secret]` of the earlier read epoch (spec/sync.md §2) or `[]`; its epochs are the label's group thing's. A claim set holding a box of another form is malformed.
- **Superseded list** (spec/crypto.md §4): a keyset's field 4 `supersedes` (spec/data-model.md §9), `set<epoch>`: each epoch `[n, nonce]` the rotation lists. A rotation commit writes the whole keyset (a replace), so the list is read from its `keys.0` delta.
- **Names digest** (spec/crypto.md §4): a keyset's field 6 `names`, 32 bytes: the unkeyed BLAKE3 of the canonical bytes of the rotation's names as the history box carries them (`[[name*], Opt([ts, node])]`, below).
- **History box** (role r, epoch e): XChaCha20-Poly1305 under `kdf("history", secret_r[e])`, nonce 24 zero bytes, AD = `[actor, role, n, nonce]`, plaintext `[[[n, secret]*], [[name*], Opt([ts, node])]]`: the earlier secrets strictly ascending by the epochs they name (by `n`, then `nonce` bytewise), each `n` below e's (a box breaking this opens to nothing), then the names (spec/crypto.md §4), each `[thing, ts, node, commit]` (the commit's key; an expiry's: the first `ts` at `until`, the holder's tid, 32 zero bytes) ascending by those fields, then the departs mark (the rotation commit's `ts` and signing node); the `secrets.0` history map holds the ciphertext.
- Suite 1 is the only suite: `suite` fields and suite bytes are 1.

## 8. Labels: steps and claim sets
```
Step     := [label_id, prev, sync_pk, write_pk, delete_pk, deposit_pk, step_key, claims_hash, sig]
ClaimSet := [[claim+], {entry: box}]
```
- Role keys (spec/sync.md §2) are Ed25519 key pairs whose 32-byte seed is the `kdf` output; `*_pk` are their raw public keys. `step_key`: the step's raw X25519 public key. `prev`: `Opt(step ID)`, `[]` in the genesis step.
- `sig`: raw Ed25519 signature by the parent's delete key (the genesis step: by its own `delete_pk`) under `"osis v1 label register"`, digest BLAKE3(canonical bytes of the array of the first eight items). **Step ID** = BLAKE3(canonical bytes of `Step`).
- **Label ID** = first 16 bytes of BLAKE3(`"osis v1 label id"` || genesis `delete_pk`).
- `claims_hash` = BLAKE3(canonical bytes of the step's `ClaimSet`). `claim`: 32 bytes, a claim public key or static entry (spec/sync.md §2), the count a power of two from 1 to `MAX_CLAIMS`, order as the registrar wrote it. The map holds an entry box (§7) per static entry listed, keyed by the 32-byte entry; every key appears in the claims.
- **Claim key pair**: the Ed25519 key pair with seed `kdf("label claim", DH(step private key, M's X25519 key), label_id || step_key)`.
- **Static entry**: `BLAKE3("osis v1 static claim" || label_id || pk)` with `pk` the key actor's raw Ed25519 signing key.
- `label.0` stores a step as the canonical bytes of `Step` and its claim set as those of `ClaimSet` (`step_record`, spec/data-model.md §9).

## 9. Inbox blobs
- **Inbox blob** (spec/crypto.md §5): prefix with expiry = the sender's corrected wall ms + `INBOX_LIFETIME` and no commitments, then the raw bytes of a sealed box (§7, not a `sealed` value) to the recipient's newest read keyset KEM key.
- AD = `[recipient, "inbox", prefix bytes]` (`"inbox"` a text string).
- Payload: the padded (§5) canonical bytes of `InboxPayload`:
  ```
  InboxPayload := [CommitBlobPlaintext, [[tid, Opt([label_id, index, [address*]]), Opt([admin_pk, write_pk])]*], [CommitBlobPlaintext*]]
  ```
  - **Position 0**: the role commit with the parts about the recipient (§4).
  - **Position 1**: for each thing it names, sorted by tid: if the thing has a label of its own (its `label.0`, never a group's holding it), that label's ID, index (uint, spec/sync.md §2) and host addresses (`address` values, spec/data-model.md §9) and, for a thing with secrets of its own, its current admin and write delete keys (spec/crypto.md §7).
  - **Position 2**: empty unless a thing the commit touches has no label of its own. Then it holds, a chain that would not fit the blob left out:
    - the author's chain certificates for the carried parts (spec/permissions.md §4), each projected to its chain deltas and without any `keys.0` but the author's own;
    - when the commit boxes the recipient (a grant, a re-seal), the current `keys.0` commit of each thing it boxes it on, projected to that delta.
- A recipient ingests the chain before the commit, only once the blob is admitted (spec/sync.md §3), and only its `roles.0`, `created.0` and `keys.0` deltas.

## 10. Links and recovery cards
```
Link := [1, seed, target, k, k_label, [address*], [peer*], ? flags]
peer := [dialable, [relay*]]
Card := [1, seed, account, home_label, [address+]]
```
- `Link` (spec/permissions.md §7): format 1, L's 32-byte seed, the target tid, K's tid, K's label ID, host addresses of K's label, and the sharer node's P2P reach for first contact: `dialable` its 32-byte dialable key, `relay` its relays as `peer://` relay items (the relay items of `reach.0`, spec/data-model.md §9, spec/sync.md §10). A redeemer with no common host dials a peer, which serves K's label as a co-reader peer (spec/sync.md §5). `flags` (uint): bit 0 single use (the redemption removes L's own grant, spec/permissions.md §7); other bits are reserved and MUST be zero; present only when nonzero (a link with `flags` 0 or a reserved bit set is malformed).
- `Card` (spec/permissions.md §7; not built, issues/recovery-redesign.md): format 1, the recovery key's 32-byte seed, the account's tid, its home label ID, host addresses.
- The label a link or card names is the first label of K or of the account (index 0, spec/sync.md §2): both are created with it.
- Caps: at most 8 addresses, 4 peers, 4 relays per peer; URLs at most 256 bytes (§13).
- Text forms: `osis://link/` or `osis://card/` followed by the unpadded base64url of the canonical bytes.

## 11. Node-to-node protocol (version 1)
### 11.1 Framing and handshake
- Each direction of the stream (spec/sync.md §10) is a sequence of frames: a 4-byte big-endian length `len`, `1 <= len <= MAX_MESSAGE`, then one canonical CBOR item of `len` bytes. A frame breaking a rule of this section is answered by Error 2 and may end the connection.
- Each side sends `Hello := ["osis", [version+], wall_ms, challenge]` as its first frame, without waiting for the other's: supported protocol versions strictly ascending (at most 16; the Hello frame at most 256 bytes), its corrected wall clock, 32 random bytes. The session uses the greatest version both list; with none in common, both close. This section defines version 1.
- Every later frame is a message `[kind, id, ...]`. `id < 2^32` is chosen by the requesting side and not reused while its request is outstanding; replies carry it. `id` is 0 in a Push and a Notify and nonzero in every request and reply, except an Error answering a frame whose id cannot be read, which carries 0; any other id 0 (or a Push or Notify with another id) is malformed. A Sub's id names its subscription and is not reused (by any request) until its Unsub is answered, a Notify `[1]` for it arrived, or its Sub was answered otherwise than by Reply `[0, ..]`; a Sub reusing a live subscription's id is answered Error 2. Either side may send requests. A request of unknown kind gets Error 11. Replies may arrive in any order.
- **Static key** of a side: the 32-byte key the transport authenticated for it (the key of the address dialed or listened on: a host's address key; a peer's dialable key, or the LAN transport key it announced). An open signature binds the opened side's static key and Hello challenge.

### 11.2 Messages
```
Error     [0, id, code]
Ok        [1, id]
Ping      [2, id, wall_ms]                     -> Pong [3, id, wall_ms]
Open      [4, id, label_id, proof]             -> Opened | Step | Error
Opened    [5, id, head, Opt(entry_box)]
Step      [6, id, step]
Register  [7, id, label_id, step, Opt(claim_set)]   -> Ok | Error
Path      [8, id, label_id, Opt(after)]        -> PathReply [9, id, [step*], more]
Upload    [10, id, label_id, [entry+]]         -> Status
Status    [11, id, [code+]]
Deposit   [12, id, label_id, blob, wrap, sig]  -> Budget [13, id, code, Opt([entries_left, bytes_left])]
Delete    [14, id, label_id, [item+]]          -> Status
Sync      [15, id, label_id, Opt(cursor), inline_limit, max_reply, [entry*], [gained*]]
                                               -> SyncReply [16, id, [event*], [want*], [code*], cursor, more] | Error
Reconcile [17, id, label_id, [range+]]         -> ReconcileReply [18, id, [range*]]
Fetch     [19, id, label_id, max_reply, [blob_id+]]     -> FetchReply [20, id, [[blob_id, Opt([blob, wrap, Opt(stamp)])]*]]
Subscribe [21, id, [label_id+]]                -> Status
Unsubscribe [22, id, [label_id+]]              -> Ok
Push      [23, 0, label_id, [event+], cursor]
Auth      [24, id, Opt(secret), session_id]      -> Reply [0, []] | Error
Call      [25, id, max_reply, method, [arg*]]  -> Reply | Error
Reply     [26, id, outcome]
Sub       [27, id, max_reply, filter]          -> Reply | Error
Unsub     [28, id, sub_id]                     -> Ok
Notify    [29, 0, sub_id, payload]

proof  := [0, sync_pk, sig] | [1, step_id, claim_pk, sig] | [2, signing_pk, sig] | [3, dialable_pk, sig]
entry  := [blob, wrap, stamp] | [blob, wrap, stamp, [replace+]]
replace := [blob_id, [[level, dsig]*], sig]
item   := [blob_id, Opt(at), [[level, dsig]*], sig]
cursor := [log_id, seq]
outcome := [0, value] | [1, code, detail*]
payload := [0, value] | [1] | [2, value]
event  := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, blob_id, at] | [3, step]
range  := [lower, upper, mode]
mode   := [0, fingerprint] | [1, [blob_id*]] | [2, [blob_id*], [blob_id*]]
```
Steps and claim sets (§8) and `entry_box` (a `box` value, §7) are their canonical bytes as byte strings; blobs are byte strings; `wrap` 57 bytes; `sig`, `dsig`, `stamp` raw 64-byte Ed25519 signatures; `*_pk` raw 32-byte keys; `at` wall ms; `log_id` 16 bytes.

- **Open** (spec/sync.md §5): `sig` under `"osis v1 label open"`, digest BLAKE3(canonical `[label_id, challenge, static_key]`) with the opened side's challenge and static key; proof 0 by a sync key, 1 by claim key `claim_pk` at step `step_id`, 2 by a key actor's signing key (its static entry), 3 by a node's dialable key under `"osis v1 co-reader open"` instead (co-reader peers only, spec/sync.md §5). An unknown label is answered Error 13. Opened carries the head (without claim set) and, for proof 2, the head's entry box for that static entry. A match at a superseded step is answered by Step with that step's child (without claim set).
- **Register**: replies Ok (also when the step already is the head), or an Error without the head (spec/sync.md §5):
  - 2 when the step's label is not the message's or the claim set does not hash to `claims_hash`;
  - 1 for a genesis step that does not verify;
  - 13 for a child step of an unknown label;
  - 9 for a step that is not a valid child of the head;
  - 14 when a genesis step's new label is outside the host's admission (spec/data-model.md §9);
  - 12 when that genesis step does not fit a storage cap (a child step that does not fit: spec/sync.md §5);
  - 4 when registrations are rate-limited.
- **Path** (opened labels): the registration path after step `after` (from the genesis step when absent) toward the head, without claim sets, at most 48 steps per reply; `more` is true when steps remain. An `after` that is neither the head nor on the path is answered Error 1.
- **Upload** and the entries of Sync: `stamp` under `"osis v1 upload"`, digest BLAKE3(canonical `[label_id, blob_id, wrap]`). Status gives one code per entry in order.
  - A relay-only entry (prefix class 2) is not stored: the receiver admits it (spec/sync.md §5), pushes it to the subscribers of the label on its other connections as a Push of one add event carrying the blob (the Push's cursor the subscription's current position) and answers 0.
  - A repeat of a blob ID it pushed under that label before the blob's expiry is answered 0 and pushed to nobody.
- **Replace** (an entry's replace list, spec/sync.md §5): each carries the signatures of a Delete item of `blob_id` without `at`, checked as for Delete except that one commitment group covered suffices. Status code 1 or 9 for a replacement's signatures refuses its entry.
- **Deposit**: `sig` by the deposit key under `"osis v1 deposit"`, digest as for a stamp. Budget reports what remains of the label's deposit budget after the request, present only when `sig` verified under the head's deposit key (spec/sync.md §5).
- **Delete**: per item, signatures under `"osis v1 delete"` over digest BLAKE3(canonical `[label_id, blob_id, Opt(at), [level*]]`), the levels those of its `[level, dsig]` pairs, ascending, distinct, within 1..3:
  - with no pair, `sig` by the head's delete key;
  - else each `dsig` by that level's delete key, verifying under the commitment at that level of at least one of the blob prefix's groups (spec/crypto.md §7), every group covered by at least one pair, and `sig` by the head's write key when any level is 3, else its sync key (spec/sync.md §5). A pair verifying under no group refuses the item.
  - `at` requests a timed delete; an `at` not after the receiver's clock deletes at once.
  - An item whose entry is not held: by the delete key, 0 when a tombstone of the blob exists (a repeated delete is idempotent), else 1; with levels, 1 (the prefix to check them against is gone).
- **Sync** (cursor sync and download, spec/sync.md §6):
  - **`cursor`** is the peer's log position for the label; `log_id` names the log instance.
    - A peer whose log has that `log_id` but was trimmed past `seq` answers Error 15.
    - One whose log has another `log_id` or does not reach `seq` yet answers Error 10.
  - **No cursor**: the reply replays the label's live entries as add events, in ascending blob ID order.
    - While such a replay has `more`, its cursor is opaque to the requester (a `cursor` the peer chose); a Sync carrying it continues the replay.
    - The last page returns the log cursor taken when the replay started.
    - A peer that no longer holds that replay answers Error 10.
  - **Lists**: `entry` lists the requester's new stamped entries (status per entry in `[code*]`), `gained` the blob IDs gained from other sources since the cursor, `want` those the peer lacks and has no tombstone for. The reply carries no add event for the requester's `entry` blobs or `gained` IDs.
  - **Inline bytes**: a blob's bytes travel inline in an add event only if its size is at most `inline_limit`; a peer omits the bytes of a blob it knows crossed this connection. A requester fetches any added blob whose bytes it lacks. Pushes use the `inline_limit` of the connection's last Sync of the label, 0 without one.
  - **`max_reply`**, in `SMALL_REPLY..=REPLY_BUDGET`, bounds the reply's frame body. A peer ends the page before an event that would pass it, so a reply asked below `REPLY_BUDGET` may hold no event, and one asked at `REPLY_BUDGET` holds at least one.
  - A first page SHOULD ask 64 KiB plus 40 bytes per `gained` and 10 per `entry`, and later pages `REPLY_BUDGET`; a Fetch 64 KiB per ID.
  - `more` true: repeat with the returned cursor.
- **Events**: 0 an entry added or a deposited one stamped, its wrap and stamp replaced (no stamp: deposited), 1 deleted, 2 a timed deletion pending at `at`, 3 a new head (without claim set). Expiry produces no event.
- **Fetch** (spec/sync.md §5): items in request order, possibly a prefix of the request when the reply would exceed `max_reply` (in `SMALL_REPLY..=REPLY_BUDGET`), possibly none below `REPLY_BUDGET`; the requester asks the rest again under `REPLY_BUDGET`.
- **Subscribe** (opened labels): the peer then sends Push with each new run of log events after the cursor of the label's last Sync on this connection that returned `more` false (else after the log head at Subscribe), with blobs as in Sync under the connection's last `inline_limit` for that label, and the relay-only entries other connections upload.
- **Client port** (kinds 24-29): served only on a node's own listeners; any other side answers them Error 11. `session_id` is 16 bytes; `secret` is exactly 32 bytes.
  - **Auth**: answered Reply `[0, []]`.
    - A main session (the unix transport, spec/sync.md §10) sends Auth without `secret`.
    - A client-actor session, on a keyed transport, sends it with its bearer secret (spec/data-model.md §9), which binds the session to the client actor of the `clients.0^` entry whose `secret_hash` is its BLAKE3, compared in constant time, `until` not passed.
    - Any other Auth is answered Error 1: no matching entry, no secret on a keyed transport, a secret on the unix transport, a second Auth of a client-actor session.
    - Past `MAX_CONNS_PER_CLIENT` authenticated sessions of one client or `max_clients` of all clients: Error 4.
    - A Call or Sub before an Auth answered by Reply is answered Error 1.
  - **End of a client-actor session**: it ends when its entry goes, its `secret_hash` changes or its `until` passes. Each request is checked at the time it runs and does not run if any of those holds.
  - **A client actor's rights**: every method of a client-actor session runs as its client actor, by that actor's rights at that time.
    - A thing the actor may not read (spec/sync.md §3, and not a kept copy it reads, spec/permissions.md §3) answers every method as a thing the node does not know.
    - A write the actor may not make is code 3, adding a thing it may not read to a group code 1, a `link` value anywhere in its write code 8.
    - A revert needs the actor's rights on every write it makes (of a thing it deletes: every aspect, and its memberships in every group both the node and the actor may write; a membership in any other group stays, as for a delete) and on everything the reverted commit touched, and lists nothing the actor may not read (code 3).
    - Methods carrying state beyond a thing the actor may read are Owner only, code 11 otherwise.
    - This is the serving node's own rule, not a validity rule: receivers judge its commits by the author node's rights (spec/permissions.md §1), and its header's actor only by whether the author node acts for it (spec/permissions.md §5.2), never by the actor's rights on what it writes.
  - **Write nonces**: a write's nonce is below 2^62, from 1 per (identity, session id).
    - A client resending a write it had no answer to sets bit 62.
    - A node that holds no write outcomes for that session answers such a write code 12 and does not run it, as it does every later marked write it does not remember until the session's next unmarked one.
    - One that holds them answers a nonce it remembers with its first result.
    - A session's write outcomes do not outlive the node process.
  - **`max_reply`** is in `SMALL_REPLY..=REPLY_BUDGET`.
    - A Reply whose message exceeds it is replaced by `[1, 5, max_reply]`.
    - A delivery whose Notify would exceed its Sub's `max_reply` is sent as `[2, source]`, and a Notify still exceeding it as `[1]`.
  - **Methods**: `method`, `arg`, `filter`, `value` and `detail` are defined by the method table (notes/client-port.md until stable).
  - **Outcome error codes**: an unknown method is `[1, 11, text]`.

    | code | meaning | detail |
    |---|---|---|
    | 1 | unknown thing | `[tid]` |
    | 2 | unknown actor | `[tid]` |
    | 3 | permission | `[tid, role]` |
    | 4 | type | `[path, text]` |
    | 5 | too large | `[limit]` |
    | 6 | not undoable | `[commit, reason]` |
    | 7 | unsynced | `[[tid*]]` |
    | 8 | invalid | `[text]` |
    | 9 | storage | `[text]` |
    | 10 | network | `[text]` |
    | 11 | unsupported | `[text]` |
    | 12 | outcome unknown: the write may have applied | `[]` |
    | 13 | refused: this session may not use the node | `[text]` |

  - **Payload**: `[0, ..]` is a delivery, `[1]` the subscription lapsed (its id is free), `[2, source]` a delivery above `max_reply`.
  - **Flow control**: spec/sync.md §6; Notifies follow the push rule.
  - **Subscriptions**: at most `MAX_SUBS` live subscriptions per connection, counted apart from open labels (Error 4 past it).
- Once one signature of a message verifies under no key the host tries (code 1), it MAY check the message's later signatures against the head's keys only (code 1 where 9 would be due).
- Code 9 refuses a signature under an earlier key of the label's role (a host answers it for some recent earlier keys, 1 past them) and carries nothing more, never the head: the signer learns the head where it opened the label (a push or Sync event, spec/sync.md §5) and signs again once it holds a newer key.
- **Status codes**:

  | code | meaning |
  |---|---|
  | 0 | ok |
  | 1 | refused |
  | 2 | malformed |
  | 3 | too large (a relay-only blob above `MAX_RELAY_BLOB`; a host answers an oversized message as malformed, 2) |
  | 4 | rate limited |
  | 5 | deposit budget full |
  | 6 | tombstoned |
  | 7 | expired |
  | 8 | label not opened |
  | 9 | key not of the head |
  | 10 | cursor invalid |
  | 11 | unsupported |
  | 12 | storage cap reached |
  | 13 | unknown label |
  | 14 | not admitted |
  | 15 | log trimmed |

- **Per-message caps**:
  - Upload, Delete and the entries of Sync: 1024 items.
  - Replace items: 1024 per Upload or Sync over all its entries.
  - Fetch: 1024 IDs.
  - `gained` and `want`: 4096.
  - Subscribe and Unsubscribe: 1024 labels.
  - Reconcile: 256 ranges; ReconcileReply: 4096.
  - A mode 1 list: at most 32 IDs. A mode 2: at most 1024 then 32. IDs strictly ascending and inside their range, `lower < upper`.
  - A peer may refuse to hold more than 4096 open labels per connection (code 4).

### 11.3 Range reconciliation
- The set reconciled is the blob IDs of the label's live entries at each side. Bounds are byte strings of at most 32 bytes compared as if right-padded with zero bytes; a range holds the IDs with `lower <= id < upper`, `upper = []` meaning the end of the ID space. Ranges in a message are sorted and disjoint.
- **Fingerprint** of a set S: the first 16 bytes of BLAKE3(`le256(sum of S mod 2^256) || le64(|S|)`), each ID read as a little-endian 256-bit integer.
- A Reconcile carrying a mode 2 range is malformed. The requester opens with one range over the whole space: mode 1 with its IDs if it holds at most 32, else mode 0. A side receiving a range:
  - mode 0: equal to its own fingerprint over the range: nothing; else, holding at most 32 IDs there: mode 1 with them; else it splits the range into 16 subranges of near-equal own counts (bounds of its choice) and sends each with mode 0, or mode 1 where it holds at most 32 (at most 8 when more than half of the mode 0 ranges of the message it answers mismatched and there were at least 16). Either mode is valid for any subrange within the list caps (§11.2).
  - mode 1 at the responder: holding at most 1024 IDs there, mode 2 with the IDs it holds that the list lacks, then the listed IDs it lacks; else it splits as above. Mode 1 at the requester, and mode 2: nothing; the requester now knows both differences for the range.
- The requester sends the ranges it must answer in further Reconcile messages (at most 256 per message) until none remain, then fetches what it lacks and uploads or relays what the responder lacks (spec/sync.md §6).

## 12. Bundles
- A bundle file (spec/sync.md §11) is the 8 ASCII bytes `osisbndl` followed by frames as in §11.1, each one record. The first record is `[0, 1]` (bundle format 1). Records:
  - `[1, label_id, [[step, Opt(claim_set)]+]]`: the registration path from the genesis step to the head;
  - `[2, blob]`: blob bytes, before the first entry naming them, once per bundle;
  - `[3, label_id, blob_id, wrap, Opt(stamp)]`: an entry (no stamp: deposited);
  - `[4, label_id, blob_id]`: a deletion; `[5, label_id, blob_id, at]`: a pending timed deletion.
- Steps and claim sets are their canonical bytes as byte strings (as in §11.2). An importer verifies paths and stamps as a host does and applies the records as a peer's log events received without a cursor: a path record after the first for its label must pass through the current head; an entry before its blob's record, or stamped before a path record of its label (its stamp checked against that path's head), is malformed; a second format record is malformed, another bundle format parks the file; records of unknown kind are skipped.

## 13. Decoder limits
- Any object: CBOR nesting at most 512 deep, values inside it at most `MAX_VALUE_DEPTH` (spec/data-model.md §5); no array or map longer than the bytes that remain.
- Blob `MAX_BLOB`; frame `MAX_MESSAGE`; a message at most 2^20 CBOR data items in all; AK `MAX_AK_BYTES`; URL 256 bytes.
- Header: each inline list at most `CHUNK_THRESHOLD` bytes, each linked one at most `MAX_LIST_BYTES`. Prefix: 65535 groups of at most 3 commitments, within the blob. Claim set: `MAX_CLAIMS` keys; a claim set with its entry boxes is at most `MAX_MESSAGE` − 64 KiB. Tree node and link page: 512 links (a tree node one length per link); tree level 48. Sequence run: `MAX_RUN` elements, a list run's `Content` closing at `CHUNK_MAX` bytes; runs without `Content` in a writer or import delta: `MAX_DELTA_BARE` elements in all (spec/crdt.md §3.3). Link and card: §10. Messages: §11.2.
