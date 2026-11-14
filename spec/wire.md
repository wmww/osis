# Wire formats
> Summary: Byte layouts of everything that leaves a node, and the table of every constant's value.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a sync ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin, 3 sync (ordered sync < read < write < admin). A purgeable-by class: 0 `nobody`, 1 `admin`, 2 `author_or_admin`, 3 `writer`. A delete level: 1, 2, 3 (spec/crypto.md §7).
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
| `MAX_LIST_BYTES` | 64 MiB (67 108 864 bytes), one linked header list's canonical encoding (§4): about a million aspects per commit, about 1.9 million commit IDs per frontier |
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
| `MAX_RELAY_BLOB` | 64 KiB (65 536 bytes), whole relay-only blob (spec/sync-ids.md §6; spec/sync-compaction.md §2) |
| `ROLE_KEEP` | 90 days |
| `INBOX_LIFETIME` | 90 days |
| `DEPOSITS_WAITING`, `DEPOSITS_WAITING_BYTES` | 32 entries, 1 MiB (1 048 576 bytes): deposits a node leaves waiting under a sync ID it clears (spec/sync-inbox.md §4) |
| `LIST_TREE_DEPTH` | 32: levels of a rotation's list tree, at most 2^32 thing lists per rotation (§4, List tree; spec/permissions.md §5.5) |
| `MAX_CHAIN_DEPTH` | 64 links from a thing up its record chain to its key actor (spec/permissions.md §1) |
| `MAX_RETENTION_ENTRIES` | 64 entries in the `rules` of one `retention^.0` delta (spec/commits.md §5) |
| `MAX_AUTHOR_ITEMS` | 32 items by author in one commit's `purge` (§4) |

### Protocol version 1 limits
Not format constants (§11). Per-message caps: §11.2.

| constant | value |
|---|---|
| `MAX_MESSAGE` | 9 MiB (9 437 184 bytes), one frame's `len` (§11.1) |
| `REPLY_BUDGET` | `MAX_MESSAGE` − 64 KiB: the greatest `max_reply` (§11.2) and the bound on a peer's untaken bytes for a push (spec/sync-streams.md §2) |
| `SMALL_REPLY` | 16 KiB (16 384 bytes): the smallest `max_reply` (§11.2) and the reply allowance of every kind without its own (spec/sync-streams.md §1) |
| `WINDOW` | 16 MiB (16 777 216 bytes) a requester keeps in flight per connection (spec/sync-streams.md §1) |
| `MAX_SUBS` | 4096 live subscriptions per connection (§11.2) |
| `MAX_CONNS_PER_CLIENT` | 8 authenticated sessions of one client actor (§11.2) |
| `MAX_PROOFS` | 256 actor proofs in one Prove or Proved (§11.2) |
| `MAX_RESUME_TAGS` | ⌊(`MAX_MESSAGE` − 64) / 33⌋ tags in one Resume (§11.2) |

### Node policy
Not format constants. A value marked recommended is advice.

| name | value |
|---|---|
| `TOMBSTONE_LIFETIME` | recommended 30 days (spec/sync-ids.md §5, §6) |
| deposit budget | recommended minimum `64 + 4 ×` (size of the current step's claim set) entries and that many × 32 KiB bytes (spec/sync-inbox.md §3) |
| `RECORD_BUDGET` | recommended 256 MiB: bytes of peer records a node keeps, least recently used evicted first (spec/sync-opens.md §3) |
| `INCARNATIONS_KEPT` | recommended 4096 ended incarnations of a node log (spec/sync-streams.md §3), oldest evicted: a cursor naming an evicted one names no position, so its holder lists from the start once |
| `MAX_DELIVERED` | 2^16 delivered relay-only commit IDs remembered (spec/sync-compaction.md §2) |
| `LOST_HEARD_WAIT_MS` | `ROLE_KEEP`: how long after a node first found a role gone by an `until` alone it drops anyway (spec/permissions.md §2) |
| `SETTLE_MS` | local policy, 30 s: how long a node leaves another node's fresh demotion or `keys.0` to its author before copying it, and a plain thing with a holder to the author of its newest edge write before giving it secrets of its own (spec/permissions.md §2, §3, §4) |
| `PASS_WAIT_MS` | local policy, recommended 1 hour: how long a complete pass waits for a peer whose record holds the sync ID (spec/sync-status.md §1) |

## 3. Creation records and agility enums
- Agility enums (spec/crypto.md §8) are values: `signing_key = enum { ed25519 1 (blob) }` (32 bytes), `signature = enum { ed25519 1 (blob) }` (64 bytes), `kem_key = enum { x25519_mlkem768 1 (blob) }` (`pk_x || pk_m`, 1216 bytes), `sealed = enum { x25519_mlkem768 1 (blob) }` (`ct_x || ct_m || AEAD`). Each encodes as `1617([1, h'...'])`.
- A **creation record** is the value `creation = struct { admin 0: tid, key 1: signing_key, nonce 2: blob, link 3: tid, account 4: bool }` holding exactly one of fields 0 and 1, and a 32-byte nonce: a thing `{0: admin, 2: nonce}` (its first admin, spec/permissions.md §1), a link's actor K `{0: admin, 2: nonce, 3: target}` (the thing it was made for, spec/permissions.md §7), a key actor `{1: key, 2: nonce}`, an account `{1: key, 2: nonce, 4: true}` (`key` its first epoch's, spec/crypto.md §3). Field 3 is only beside field 0; field 4 only ever true and only beside field 1. Its canonical encoding is what the tid hashes: tid = first 15 bytes of BLAKE3(canonical bytes). `created.0` holds this value (spec/data-model.md §9); a `created.0` whose read does not hash to its tid, holds not exactly one of fields 0 and 1, a field 3 not a tid or beside field 1, a field 4 not `true` or beside field 0, or any field other than 0 to 4, is bad input (a closed struct, not parked); an unknown `signing_key` case parks the thing (spec/versioning.md §2).
- A link key's nonce is `kdf("creation nonce", seed, "")`; a node's or an account's is random.
- **Record blob** (spec/permissions.md §4): a blob whose plaintext, in place of a `CommitBlobPlaintext`, is `RecordBlobPlaintext := ["records", [creation+]]`, the creation records ascending by tid, distinct, each read as `created.0` reads one; with no commitments and no expiry, durable. A reader takes each record's tid from its hash: a record needs no signature. Anything else is bad input.

## 4. Commits
```
Header    := [version, author, actor, kind, ts, form, expires, aspects,
              purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation]
Aspect    := [tid, ak, lo, hi, Retention, keys, hash, replaces]
Retention := by
DeleteKey := [level, pk]
PurgeItem := [tid, ak] | [tid, ak, actor] | [tid, ak, ts, source]
Rotation  := [signing_key, kem_key, [epoch_id+], [commit_id*], list_root]
CommitBlobPlaintext := [Header, signature, Opt(inner), [signature*], [Section*]]
Section   := [[ai+], [chain*], wrap, ciphertext]
Part      := [ai, delta]
```
Header fields by position:
0. `version`: uint, the format version (1).
1. `author`: tid of the signing key actor: an account, or a key actor other than an account signing as itself (a node only for its own node thing's aspects, spec/permissions.md §1). 2. `actor`: tid of the actor it acts for (spec/permissions.md §5.2); in a role commit (`kind` 1) equal to `author`, else bad input.
3. `kind`: 0 content, 1 role, 2 content compaction snapshot, 3 role compaction snapshot (spec/commits.md §2).
4. `ts` (spec/crdt.md §2.2). 5. `form`: 0 commit form, or `[1, nonce]` session form with the session's 16-byte nonce (spec/commits.md §3).
6. `expires`: `Opt(T)`, the commit's expiry, wall ms (spec/commits.md §6).
7. `aspects`: `[Aspect+]` sorted by the canonical bytes of `[tid, ak]`, distinct.
8. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`; `[tid, ak, actor]` those of them whose commit's purge actor is `actor` (spec/permissions.md §6: the actor its header names); `[tid, ak, ts, source]` the delta on that aspect of the commit stamped `ts` whose own writes are `source`'s (spec/crdt.md §2.1: 31 bytes, a session; 32, a commit-form commit's ID; else bad input), one commit per stamp and source on an aspect (spec/commits.md §5 Purge).
9. `undoes`: `Opt(commit_id)`.
10. `blind`: 16 random bytes (spec/crypto.md §7).
11. `keys`: `[DeleteKey*]` sorted by canonical bytes, distinct: the delete keys of the commit's deltas (spec/crypto.md §7), `pk` a valid Ed25519 key (§1, spec/crypto.md §1), at most one at level 2 (the author chain); a key no aspect lists is bad input.
12. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9); present iff the commit is a role commit carrying an explicit removal or an explicit edge write that audits (spec/permissions.md §5.1 step 4; a writer rule: a receiver checks only that it sits on a role commit). A value that does not decode as a `frontier` is bad input.
13. `ephemeral`: `Opt(uint)`, the ephemeral marker (spec/commits.md §2): 0 an ephemeral commit, 1 a relay-only one. Present only with `kind` 2 and `form` 0, or `kind` 0, no `purge`, no list by link and no `created.0` aspect; every aspect's retention is `writer`, with the levels it calls for; a relay-only commit is of `kind` 2 with no `expires` and no `undoes`, and a delta of it linking a page is bad input (its deltas never page, spec/commits.md §2). Anything else is bad input.
14. `epoch`: `Opt(epoch_id)`, the epoch an account author signs at (spec/crypto.md §9; 32 bytes: the minting rotation's commit ID, 32 zero bytes for the first epoch); present iff the author's creation record marks an account, else bad input.
15. `rotation`: `Opt(Rotation)`, present only on a role commit of an account (else bad input): the new epoch's signing key and KEM key (spec/crypto.md §3); the epochs it supersedes, ascending, distinct, the header's `epoch` among them (else bad input); actor equal to author and a `keys.0` delta on the author (else bad input); the fork rotations it names (a merge), ascending, distinct; `list_root`, 32 bytes, the root of its list tree (below). Its commit ID names the epoch it mints.

Aspect fields: `tid`; `ak` (text, spec/data-model.md §2, at most `MAX_AK_BYTES`); `lo`, `hi`: the counter range (`lo = hi = 0` for kinds 2, 3; else `1 <= lo < hi`); `Retention`: `by`, the purgeable-by class (spec/commits.md §5); `keys`: `[ki*]`, ascending indices into the header's `keys`: one per level the retention calls for (spec/crypto.md §7), exactly those levels, else bad input; `hash`: the 32-byte delta hash of its one delta. `replaces`: `Opt(commit_id)`, the fire the delta claims to replace (spec/commits.md §5 Signals), allowed only on a durable signal's delta of a durable commit; anywhere else the part is bad (spec/commits.md §2).

- **Inline or link**: `aspects`, `purge`, `keys` and the frontier are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the dedup secret of the header's `actor`. A decoder rejects an inline list above the threshold or a link to one at or below it or above `MAX_LIST_BYTES`; a writer refuses such a commit. A linked frontier's encoding is exactly `{0: set<32-byte commit ID>}`; anything else is bad input. Header-list chunks carry the commitments of §5: every link of a list's tree names, as its delete keys, the header's level-2 key alone (none when the header lists none); any other is bad input.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the author's key (an account's: the signing key of the epoch the header names) under `"osis v1 commit"` over the digest below.
- The commit signature of an account's commit signs BLAKE3(commit ID ‖ `inner` ‖ each merge signature) (spec/crypto.md §2); every other commit's signs the commit ID.
- **Inner signature** (spec/crypto.md §3): `inner` is present iff the author is an account (else bad input): 95 bytes, XChaCha20-Poly1305 under `kdf("inner key", inner secret, commit ID)`, nonce 24 zero bytes, no AD, of the node's tid (15) then its raw Ed25519 signature under `"osis v1 inner"` over the commit ID (64).
- **Merge signatures**: one `signature` per fork rotation the header's `rotation` names, in that order, each under `"osis v1 merge"` over the commit ID by the signing key that fork mints (spec/crypto.md §9); empty without a rotation; another count is bad input. A header-only copy of a rotation (spec/sync-judgement.md §1) carries them.
- **List tree** (spec/permissions.md §5.5): a binary Merkle tree of depth `LIST_TREE_DEPTH` whose leaves are a rotation's thing lists, each at a random distinct index below 2^`LIST_TREE_DEPTH`.
  ```
  ThingList := [tid, [commit_id*] | LINK, salt]
  ThingCert := [rotation_id, index, [hash*], ThingList]
  ListBlobPlaintext := ["list", [ThingCert+]]
  ```
  - `ThingList`: the thing, the commit IDs ascending and distinct (inline iff its canonical encoding is at most `CHUNK_THRESHOLD`, else a LINK to a chunk tree of it as for a linked frontier, keyed by the thing's dedup secret), a fresh random 16-byte `salt`.
  - Leaf = BLAKE3(`"osis v1 list leaf"` || canonical bytes of the `ThingList`); an interior node = BLAKE3(`"osis v1 list node"` || left || right). Every subtree holding no leaf hashes to a fresh random 32-byte value. `list_root` is the root.
  - `ThingCert`: the rotation's commit ID, the leaf's index (uint), the `LIST_TREE_DEPTH` sibling hashes from the leaf up; it verifies when folding the leaf with them by the index's bits (bit k set: the sibling is on the left at height k) gives the rotation's `list_root`. A cert that does not verify is bad input.
  - A list blob (spec/sync-judgement.md §1) is a blob whose plaintext, in place of a `CommitBlobPlaintext`, is `ListBlobPlaintext`, with no commitments and no expiry.
- **Commit blob** plaintext: `CommitBlobPlaintext`: one blob carries the whole commit, every part sealed to its thing's readers (spec/sync-judgement.md §1).
  - A `Section` holds the parts of one thing: `[ai+]` the aspect indices of its parts, ascending, distinct, each with a part inside; `[chain*]` the thing's derivation chain (spec/crypto.md §3) as the writer knows it, nearest first (empty for an actor with secrets of its own or a key actor; at most `MAX_CHAIN_DEPTH`, no tid twice: else bad input); `ciphertext` = XChaCha20-Poly1305 of the canonical `[Part*]` list under a fresh random 32-byte section key, nonce 24 zero bytes (the key encrypts this one plaintext and nothing else), AD = the commit ID; `wrap` = a random 24-byte nonce `||` XChaCha20-Poly1305 of the section key under `kdf("section", read secret of the thing)` (its own, or derived from its base actor's by tid, spec/crypto.md §3) at the newest epoch the writer holds (a rotation's section under the epoch it supersedes, spec/crypto.md §5), that nonce, AD = the commit ID: 72 bytes. Sections sorted by their first `ai`; an aspect in two sections is bad input; zero sections is allowed (every delta purged). A copy (per-sync-ID or certificate, spec/sync-judgement.md §1) is one section of its parts, with an empty chain, its `wrap` under `kdf("section", blob key)` in place of a read secret: whoever opens a wrap of the blob reads it.
  - A reader tries, per section, the read secrets it holds of the section's thing, those derived by tid through the listed chain from the epochs it holds of any member of it (the thing's record may be inside the section; a member given secrets of its own since holds the derived epoch in its history), newest first, and the blob key. Parts that open on an aspect the section does not list, or a listed aspect with no part, are bad input. A section no held secret opens is kept as it is: a non-reader learns nothing of it beyond its size, `ai` list and chain, and copies it verbatim into a fresh encryption of the commit.
  - A `Part` holds one delta: `ai` indexes `aspects`, `delta` is the embedded `Delta` or `Snapshot` array (spec/crdt.md §3.2, §8) whose canonical bytes hash to that aspect's `hash`. Within a section parts sorted by `ai`, distinct.
  - The blob's prefix commitment groups are those of the delete keys its sections' aspects list (§5); its expiry is the header's `expires` (exceptions: §5). The whole commit stays within `MAX_BLOB` (a writer pages its deltas, spec/crdt.md §8, and refuses a commit that still does not fit): about 150 000 small changes on one thing, or about 6 500 things.
- A header violating a rule of spec/commits.md §2, §5 or §6 is bad input:
  - an aspect of the wrong class for its kind (`created.0` fits either kind);
  - `created.0` in a kind without own writes or with the ephemeral marker;
  - a role compaction snapshot of `roles.0`;
  - a role-class, `addenda.0`, `retention^.0`, `purge.0` or `released.0` aspect whose retention is not its fixed one (spec/commits.md §5);
  - `expires` on a commit with such an aspect but `released.0`;
  - `released.0` in a commit that is not a release request: one of kind 0 (content), durable, with `released.0` aspects alone, no purge item, and `expires` = `wall_ms(ts) + ROLE_KEEP` (spec/commits.md §5 Destruction);
  - `nobody` on an aspect other than `created.0` without fixed retention (spec/commits.md §5);
  - a content compaction snapshot's delta without fixed retention whose `by` is not writer;
  - `expires` or a purge item on a role commit;
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
| 25 | 1 | class: 0 durable, 1 ephemeral, 2 relay-only (spec/sync-ids.md §1); any other value is bad input |
| 26 | 2 | n: number of commitment groups, le16 |
| 28 | … | n groups, each: a count byte m (0..3) then 33·m commitments: level byte (1..3) `||` 32-byte blinded delete key (spec/crypto.md §7), levels strictly ascending within a group |

- The ciphertext runs from the end of the groups to the end of the blob: XChaCha20-Poly1305 under the blob key, nonce 24 zero bytes, AD = the prefix bytes, plaintext = the padded plaintext. **Blob ID** = BLAKE3(whole blob).
- **Padding** (Padmé; Nikitin et al., PURBs): for a plaintext P, let `L = len(P) + 1`, `E = floor(log2 L)`; if `E = 0`, `padme(L) = L`; else with `S` the bit length of `E` and `m = 2^(E - S) - 1`, `padme(L) = (L + m) & ~m`. The padded plaintext is `P || 0x80 || 0x00^(padme(L) - L)`. To unpad: strip trailing `0x00` bytes, then one `0x80`, which MUST be present; the padded length MUST equal `padme(len(P) + 1)`. Anything else is bad input.
- Plaintext per blob kind: commit blob `CommitBlobPlaintext` (§4); chunk: the raw chunk bytes; tree node and link page: §6; page: §6; inbox blob: §9 (its ciphertext is a sealed box, not the AEAD above).
- Class: a commit blob's class is that of its header's ephemeral marker (none: durable, 0: ephemeral, 1: relay-only); a mismatch is bad input. Inbox blobs are durable; a chunk, tree node, page or link page has the class of the commit whose delta introduced it. A commit blob's expiry `T`: none for a header-only blob (no section); else a relay-only commit's header `ts` (wall ms) plus `MAX_DRIFT` (its header carries no `expires`), any other commit's header `expires`; any other is bad input.
- Commitments, blinded by the blob's own salt and its blind (a commit blob: its header's; a chunk, tree node, page or link page: its thing blind), one per level within a group (spec/crypto.md §7):
  - a commit blob carries one group per distinct delete-key set among the aspects its sections list (opened or not), each group the keys of that set in header key order, groups in order of their first aspect; a `nobody` aspect's set is empty, so its group is (a Delete by level then never verifies, spec/sync-ids.md §6); a header-only blob carries no group;
  - a chunk, tree node or page carries one group: the delete keys of the delta that created it;
  - a chunk or tree node of a linked header list (§4) carries one group holding the commitment of the commit's level-2 key only (empty when the header lists none); its expiry is the commit's `expires`.
- **Wrap**: XChaCha20-Poly1305 under `kdf("wrap", read secret)` (the read secret of the sync ID's thing), nonce = first 24 bytes of the blob ID, empty AD, plaintext `suite (1) || blob key (32) || order (8, little-endian)`: 57 bytes. A filler is 57 random bytes.
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
- **`secrets.0` box** (spec/crypto.md §4), a `box` value (spec/data-model.md §9) keyed by `box_key`. AD = `[actor, holder, role, n, nonce, form]` with the key's epoch `[n, nonce]` and `form` = `[0, Opt([kn, knonce]), suite]` for the sealed form (the recipient keyset epoch, none for a key actor other than an account; an account's epoch name, spec/crypto.md §3, for an account) or `[1, [sn, snonce]]` for the symmetric form (the epoch of s) or `[2, [[kn, knonce]+], suite]` for the joint form (its keysets, ascending).
  - Sealed payload: `[role, n, secret]`, secret 32 bytes, naming the epoch (n, nonce of the secret under the actor's tid and the role, spec/crypto.md §4); a `secrets.0` box's names its key's (role, epoch).
  - Joint: the sealed payload sealed to the last keyset's KEM key, that sealed box sealed to the one before's, and so on to the first's, each under the box's one AD.
  - Symmetric `wrap`: XChaCha20-Poly1305 under `kdf("box", s)`, nonce = first 24 bytes of BLAKE3(AD), plaintext `suite (1) || secret (32)`: 49 bytes.
  - For an account holder, `[sn, snonce]` of the symmetric form is its epoch name (spec/crypto.md §3), `s` its role secret at that epoch.
  - Symmetric `possession`: present iff the holder is not a key actor other than an account: a `signature` by the possession key of s (spec/crypto.md §4, Holder actors) under `"osis v1 possession"`, digest BLAKE3(canonical `[actor, holder, role, n, nonce, form, wrap]`), the AD's items then the wrap.
- **Entry box** (spec/sync-ids.md §2): a `box` value in the sealed form with no keyset epoch, AD = `[sync_id, step_key, form]`, payload `[role, n, secret, earlier, sync]` with the read role, `earlier` `[n, secret]` of the earlier read epoch (spec/sync-ids.md §2) or `[]`, `sync` `[n, secret]` of the sync epoch whose key the step registers; its epochs are the sync ID's thing's. A claim set holding a box of another form is malformed.
- **Superseded list** (spec/crypto.md §4): a keyset's field 4 `supersedes` (spec/data-model.md §9), `set<epoch>`: each epoch `[n, nonce]` the rotation lists. A rotation commit writes the whole keyset (a replace), so the list is read from its `keys.0` delta.
- **Possession proof** (spec/crypto.md §4, Possession): a keyset's field 7 `proofs`, `map<tid, possession_proof>`: per holder actor M of the rotated actor, `{ keyset: epoch of M's keyset k of the keyset's role, signature }`, the signature by the possession key of k's secret under `"osis v1 possession"`, digest BLAKE3(canonical `[actor, M, role, keyset]`), the keyset value with an empty `proofs`.
- **Left out** (spec/crypto.md §4, Holder actors): a keyset's field 8 `left_out`, `map<tid, set<epoch>>`: per holder actor M the rotation left out of the keyset's role, the epochs `[n, nonce]` of M's keysets of that role it records M left out at; empty for every other rotation. A proof's digest covers it.
- **Names digest** (spec/crypto.md §4): a keyset's field 6 `names`, 32 bytes: the unkeyed BLAKE3 of the canonical bytes of the rotation's names as the history box carries them (`[[name*], Opt([ts, author, blind])]`, below).
- **History box** (role r, epoch e): XChaCha20-Poly1305 under `kdf("history", secret_r[e])`, nonce 24 zero bytes, AD = `[actor, role, n, nonce]`, plaintext `[[[n, secret]*], [[name*], Opt([ts, author, blind])]]`: the earlier secrets strictly ascending by the epochs they name (by `n`, then `nonce` bytewise), each `n` below e's (a box breaking this opens to nothing), then the names (spec/crypto.md §4), each `[ts, author, commit, holder, void]` (the edge write's commit key, the holder whose edge it writes, and whether it is void, a bool), ascending by those fields, then the departs mark (the rotation commit's `ts`, author and header `blind`); the `secrets.0` history map holds the ciphertext.
- Suite 1 is the only suite: `suite` fields and suite bytes are 1.

## 8. Sync IDs: steps and claim sets
```
Step     := [sync_id, prev, sync_pk, write_pk, delete_pk, deposit_pk, step_key, claims_hash, sig]
ClaimSet := [[claim+], {entry: box}]
```
- Role keys (spec/sync-ids.md §2) are Ed25519 key pairs whose 32-byte seed is the `kdf` output; `*_pk` are their raw public keys. `step_key`: the step's raw X25519 public key. `prev`: `Opt(step ID)`, `[]` in the genesis step.
- `sig`: raw Ed25519 signature by the parent's delete key (the genesis step: by its own `delete_pk`) under `"osis v1 sync step"`, digest BLAKE3(canonical bytes of the array of the first eight items). **Step ID** = BLAKE3(canonical bytes of `Step`).
- **Sync ID** = first 16 bytes of BLAKE3(`"osis v1 sync id"` || genesis `delete_pk`).
- `claims_hash` = BLAKE3(canonical bytes of the step's `ClaimSet`). `claim`: 32 bytes, a claim public key or static entry (spec/sync-ids.md §2), the count a power of two from 1 to `MAX_CLAIMS`, order as the registrar wrote it. The map holds an entry box (§7) per static entry listed, keyed by the 32-byte entry; every key appears in the claims.
- **Claim key pair**: the Ed25519 key pair with seed `kdf("sync claim", DH(step private key, M's X25519 key), sync_id || step_key)`.
- **Static entry**: `BLAKE3("osis v1 static claim" || sync_id || pk)` with `pk` the key actor's raw Ed25519 signing key.
- `sync.0` stores a step as the canonical bytes of `Step` and its claim set as those of `ClaimSet` (`step_record`, spec/data-model.md §9).

## 9. Inbox blobs
- **Inbox blob** (spec/crypto.md §5): prefix with expiry = the sender's wall ms + `INBOX_LIFETIME` and no commitments, then the raw bytes of a sealed box (§7, not a `sealed` value) to the recipient's newest read keyset KEM key.
- AD = `[recipient, "inbox", prefix bytes]` (`"inbox"` a text string).
- Payload: the padded (§5) canonical bytes of `InboxPayload`:
  ```
  InboxPayload := [CommitBlobPlaintext, [[tid, Opt(sync_id), Opt([admin_pk, write_pk])]*], [CommitBlobPlaintext*], [creation*], Opt([dialable, [url*]]), [[sync_id, sig]*]]
  ```
  - **Position 0**: the role commit with the parts about the recipient (§4).
  - **Position 1**: for each thing it names, sorted by tid: if the thing has a sync ID of its own (its `sync.0`, never a group's holding it), that sync ID and, for a thing with secrets of its own, its current admin and write delete keys (spec/crypto.md §7).
  - **Positions 2 and 3**: empty unless a thing the commit touches has no sync ID of its own and the recipient reads it now, as the sender judges it. A recipient holding less than read on every thing the commit touches (sync alone, or removed) gets them empty: the box and the sync IDs are all it takes (spec/sync-inbox.md §2). Otherwise they hold, a chain that would not fit the blob left out:
    - the author's chain certificates for the carried parts (spec/permissions.md §4): its commits, each projected to its chain deltas and without any `keys.0` but the author's own, in position 2, and its creation records, ascending by tid and distinct, in position 3;
    - when the commit boxes the recipient (a grant, a re-seal), the current `keys.0` commit of each thing it boxes it on, projected to that delta, in position 2.
  - **Position 4**: the sending node's dialable key (32 bytes) and its URLs (each at most 256 bytes, at most 16), a dial hint for the recipient (spec/sync-inbox.md §2); absent when the sender publishes none.
  - **Position 5**: **removal signatures**, one per sync ID of position 1 on whose thing the commit lowers the recipient below sync or removes it, ascending by sync ID: `sig` under `"osis v1 removal"` by the delete key of the newest step of that sync ID the sender records, digest BLAKE3(canonical `[sync_id, recipient, commit_id]`), `recipient` the recipient's tid and `commit_id` the commit's of position 0; empty otherwise, and from a sender that is no admin of the thing (spec/sync-judgement.md §6 Stops).
- A recipient ingests the chain before the commit, only once the blob is taken (spec/sync-inbox.md §2), and only its records, `roles.0` and `keys.0` deltas and accounts' rotations.
- **Stranded notice** (spec/permissions.md §4): an inbox blob whose payload is `StrandedNotice := ["stranded", sync_id, holder, HolderKeys]` (flattened: `HolderKeys` is two positions) in place of an `InboxPayload`: the sync ID the holder (an actor tid) is stranded on, and its holder keys. It carries no role commit and asks only for a re-seal the recipient judges itself.
- **Holder keys**: `HolderKeys := [CommitBlobPlaintext*], [creation*]`: the holder's current `keys.0` commits (its newest `keys.0` write and the rotation commits of its newest keyset per role), each projected to its `keys.0` delta on the holder, with their authors' chain certificates for those deltas, each projected to its chain deltas (as position 2 of `InboxPayload`); then that chain's creation records, ascending by tid, distinct. A receiver ingests only what is on things in the holder's authority chain as it judges it while taking them (spec/permissions.md §4): `keys.0` deltas on the named holder and on the authors of the holder's `keys.0` commits carried (their cards), records, and `roles.0` deltas, each kept only if judged valid; it ignores the rest.

## 10. Links
```
Link := [1, seed, target, k, k_sync_id, [peer*], ? flags]
peer := [dialable, [relay*]]
```
- `Link` (spec/permissions.md §7): format 1, L's 32-byte seed, the target tid, K's tid, K's sync ID, and the sharer node's P2P reach for first contact: `dialable` its 32-byte dialable key, `relay` its relays as `peer://` relay items (the relay items of `reach.0`, spec/data-model.md §9, spec/sync-transport.md §3). The redeemer dials a peer, which serves K's sync ID as a peer that reads it (spec/permissions.md §7). `flags` (uint): bit 0 single use (the redemption removes L's own grant, spec/permissions.md §7); other bits are reserved and MUST be zero; present only when nonzero (a link with `flags` 0 or a reserved bit set is malformed).
- The sync ID a link names is K's home sync ID (spec/sync-ids.md §2): K is created with it.
- Caps: at most 4 peers, 4 relays per peer; URLs at most 256 bytes (§13).
- Text form: `osis://link/` followed by the unpadded base64url of the canonical bytes.

## 11. Node-to-node protocol (version 1)
### 11.1 Framing and handshake
- Each direction of the stream (spec/sync-transport.md §1) is a sequence of frames: a 4-byte big-endian length `len`, `1 <= len <= MAX_MESSAGE`, then one canonical CBOR item of `len` bytes. A frame breaking a rule of this section is answered by Error 2 and may end the connection.
- Each side sends `Hello := ["osis", [version+], wall_ms, challenge]` as its first frame, without waiting for the other's: supported protocol versions strictly ascending (at most 16; the Hello frame at most 256 bytes), its wall clock, 32 random bytes. The session uses the greatest version both list; with none in common, both close. This section defines version 1.
- Every later frame is a message `[kind, id, ...]`. `id < 2^32` is chosen by the requesting side and not reused while its request is outstanding; replies carry it, and a reply naming no request of the receiver's outstanding is dropped, never answered, as is a malformed reply or push; a malformed request is answered Error 2. `id` is 0 in a push (Notify, Stream, Applied, Digest, Members) and nonzero in every request and reply, except an Error answering a frame whose id cannot be read, which carries 0; any other id 0 (or a push with another id) is malformed. A Sub's id names its subscription and is not reused (by any request) until its Unsub is answered, a Notify `[1]` for it arrived, or its Sub was answered otherwise than by Reply `[0, ..]`; a Sub reusing a live subscription's id is answered Error 2. Either side may send requests. A request of unknown kind gets Error 11. Replies may arrive in any order, except a stream's (§11.2, Pull).
- **Static key** of a side: the 32-byte key the transport authenticated for it (the key of the address dialed or listened on: a peer's dialable key, or the LAN transport key it announced). An open signature binds its signer's side, the other side's Hello challenge and the listener's static key.

### 11.2 Messages
```
Error     [0, id, code]
Ok        [1, id]
Ping      [2, id, wall_ms]                     -> Pong [3, id, wall_ms]
Register  [7, id, sync_id, step, Opt(claim_set)]   -> Ok | Error
Status    [11, id, [code+]]
Delete    [14, id, sync_id, [ditem+]]          -> Status
Fetch     [19, id, sync_id, max_reply, [blob_id+]]     -> FetchReply [20, id, [[blob_id, Opt([blob, wrap, Opt(stamp)])]*]]
Auth      [24, id, Opt(secret), session_id]      -> Reply [0, []] | Error
Call      [25, id, max_reply, method, [arg*]]  -> Reply | Error
Reply     [26, id, outcome]
Sub       [27, id, max_reply, filter]          -> Reply | Error
Unsub     [28, id, sub_id]                     -> Ok
Notify    [29, 0, sub_id, payload]
Stranded  [30, id, sync_id, holder, HolderKeys] -> Ok
Suspect   [31, id, sync_id, [suspect+]]       -> Ok
Prove     [32, id, [actor_proof*]]             -> Proved | Error
Proved    [33, id, [actor_proof*]]
Resume    [34, id, nonce, [tag*]]             -> Resumed | Error
Resumed   [35, id, nonce, Opt(tag)]
Beacons   [36, id, generation, Opt(base), f, lo, hi, gcs, more]  -> Shared
Offer     [37, id, [item+]]                    -> Shared
Lost      [38, id, [[sync_id, Opt(cursor)]+]]  -> Shared
Shared    [39, id, [[code, Opt(tag), Opt(grant), Opt(sig)]+]]
NoRecord  [40, id]                             -> Shared
Pull      [41, id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral]
                                               -> PullReply [42, id, [[sync_id, event]*], Opt(cursor), whole, trimmed, more, report, [join*]]
Stream    [43, 0, [[sync_id, event]*], Opt(cursor), report, seq]
Applied   [44, 0, cursor]
Digest    [45, 0, digest]
Members   [46, 0, [sync_id*], more]

actor_proof := [creation, key, sig]
item   := [0, hit, Opt(sig)] | [1, sync_id, [hit+]] | [2, sync_id, blob, wrap, sig] | [3, sync_id, Opt(step_id), key, sig] | [4, hit, signing_pk, sig]
grant  := [Opt(entry_box), [step+]]
join   := [sync_id, Opt(cursor)]
ditem  := [blob_id, [[level, dsig]*], sig]
outcome := [0, value] | [1, code, detail*]
payload := [0, value] | [1] | [2, value]
suspect := [thing, ak, digest]
event  := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, full] | [3, step] | [4, blob_id, code]
```
Kinds 4-6, 8-10, 12, 13, 15-18 and 21-23 and status codes 10 and 15 are retired: never sent, never reused; a retired kind is unknown (answered Error 11).
Steps and claim sets (§8) and `entry_box` (a `box` value, §7) are their canonical bytes as byte strings; blobs are byte strings; `wrap` 57 bytes; `sig`, `dsig`, `stamp` raw 64-byte Ed25519 signatures; `*_pk` raw 32-byte keys.

- **Prove** (spec/sync-opens.md §2, Connection proofs): dialer to listener, at most one per connection (a second is answered Error 2). `creation` is the proving key actor's creation record (§3): the actor is its tid. `key` the signing key that made `sig`: the record's own, or for an account its signing key at an epoch (open at the verifier, spec/sync-opens.md §2). `sig` by `key` under `"osis v1 connection proof"`, digest BLAKE3(canonical `[by_listener, challenge, listener_key]`): `by_listener` 0 for a dialer's proof and 1 for a listener's, `challenge` the verifier's Hello challenge, `listener_key` the listener's static key. A verifier checks proofs in order and stops at the first that does not verify: it and those after it prove nothing, those before it stand. A message carries at most `MAX_PROOFS` proofs; past it it is refused whole. A node sends its own proof first (only to a node of its own account, spec/sync-opens.md §2), then its account's, then its key actors by ascending tid, as many as fit. **Proved** carries the listener's proofs, possibly none, under the same rules. A node serving no identity answers none.
- **Beacons** (spec/sync-opens.md §5): one page of generation `generation` of a side's filter: a Golomb-Rice coded multiset of `f`-bit values over `[lo, hi)`, Rice parameter 8, each value's gap from the last (from `lo` first) as a unary quotient of 1-bits, a 0-bit and 8 remainder bits, most significant first, the last byte padded with fewer than 8 zero bits. `more` is true on every page but the last; pages are consecutive from `lo` 0 to `hi` `2^f`. `base` absent: a whole filter, `f` is `ceil(log2(n)) + 8` of its n entries (n = 0: 8); present: additions to generation `base`, at the same `f`, at most the whole filter's n entries in all. A filter past 2^22 entries, a page out of order, a gap past `hi`, or a width or additions count breaking this is answered Error 2 and closes the connection. Shared answers each page, its code 0, or 13 for a `base` not held.
- **Offer**: `hit` 32 bytes, at most 1024 items and 256 hits in an item. A Hit's `sig` is the proof of a sync key's or a claim's credential (spec/sync-opens.md §4): an **open signature** under `"osis v1 sync open"`, digest BLAKE3(canonical `[side, sync_id, challenge, static_key]`) with `side` its signer's (0 the dialer, 1 the listener), the other side's Hello challenge and the listener's static key; absent for other credentials (a read secret's or a sync-key proof's Hit proves its secret itself). A Static item (`[4, ...]`) is a Hit on a key actor's static entry carrying the key actor's signing key and an open signature by it, digest as for a Hit's; it opens only where that key's static entry is the credential hit. A Behind item (`[3, ...]`, spec/sync-ids.md §6) carries a credential key `key` of the step it names (a sync key, a claim, or a key actor's signing key; naming none, a sync key or a key actor's signing key) and an open signature by it, digest as for a Hit's. A Deposit item (`[2, ...]`, spec/sync-inbox.md §3) carries a durable or ephemeral blob (`blob`, `wrap`, `sig` by the deposit key, below: Deposit item), at most `MAX_BLOB`; the Offer as a whole fits `MAX_MESSAGE`. Shared gives one code per item in order, a 32-byte tag for a Hit accepted, none for a ByRole or Deposit; for a Hit accepted on a sync key, a claim or a static entry also `sig`, an open signature (digest as for a Hit's, with the replier's side) by the sync key of the replier's step (spec/sync-opens.md §5), absent otherwise; code 14 refuses one, for no stated reason; a Deposit item is answered 0 (taken), 14, or 4, 5 or 12 (refused for now). A Hit accepted on a static entry also carries `grant` when the answering side holds the head's claim set: the head's `entry_box` for that entry and the sync ID's path from its genesis step to that head (without claim sets). A Behind item is answered 0 with `grant` carrying no `entry_box` and the steps after the named one through the first under another sync key (without claim sets), or, by a key actor's signing key naming no step, 0 with `grant` as a Static item's accepted Hit carries; 13 for a sync ID not kept there; 4 past the Offer's step bound (spec/sync-ids.md §6: ⌊`REPLY_BUDGET` / 326⌋ steps, 326 bytes a step's greatest encoding as a byte string); else 14, with nothing; no other answer carries one.
- **Lost**: at most 1024 items, `cursor` at most 256 bytes: where the member stopped for the receiver (spec/sync-opens.md §6). Shared answers 0 per item.
- **NoRecord** (spec/sync-opens.md §3): from a dialer that keeps no record for this listener; id `2^31`.
- **Shared-set request ids**: `id`s of Beacons, Offer, Lost, NoRecord, Pull and a Fetch of stream bodies are chosen by each side with its top bit set, so they cannot equal an id of that side's other requests. An Error or FetchReply with such an id answers that request. A side keeping no shared set on the connection (a listener before the dialer's NoRecord or a record) answers each of them Error 14.
- **Pull** (spec/sync-streams.md §4, Stream), between two nodes that read the sync IDs they share, and from a reader to a peer that cannot read them: a `cursor` (here and in `join`, PullReply, Stream and Applied) is at most 256 opaque bytes the answering node sealed; `max_reply`, in `SMALL_REPLY..=REPLY_BUDGET`, bounds the reply's frame body: a server ends the page before an event that would pass it, so a reply asked below `REPLY_BUDGET` may hold no event, and one asked at `REPLY_BUDGET` holds at least one. PullReply carries, in log order, the events after `cursor` of each member of the connection's shared set, and of each `join`'s member after the join's cursor (from the start of the log when it has none); with no `cursor`, or any cursor of the Pull (its own or a join's) that names no position of the server's log, every member from the start, `whole` true, joins ignored; also so when any cursor of the Pull names a position below the server's deletion horizon (spec/sync-streams.md §3), with `trimmed` true. Its `cursor` is the position the reply covers for the stream; its `join` list names each join not at that position: one still in pages, with its own cursor, to name again in the next Pull, or one the server does not share, with none. `more` true: pull again from the returned cursors. `ephemeral` true: the reply also lists the live entries of the ephemeral class of every member; every join lists its member's. Ephemeral entries count against `max_reply` with the rest; what does not fit follows in later replies or Streams. `follow` true: once a reply has `more` false, the server pushes each later run of events as a Stream from the reply's cursor, under the push rule of spec/sync-streams.md §2, until the next Pull. A Stream with a cursor carries `seq`, the number of Streams with a cursor the server sent on the connection since its last PullReply (0 in one without a cursor); a requester applies it only in that order (spec/sync-streams.md §4). `report` asks for Applied once the requester applied and stored the message's cursor. Events (below) carry an add only for an entry whose bytes the server holds, its bytes inline only if its size is at most `inline_limit` and not for a blob that crossed this connection; a requester fetches any added blob whose bytes it lacks. A Stream with no `cursor` carries a relay-only entry (spec/sync-compaction.md §2), which no position names. A Stream with a `cursor` and no events moves the stream there and asks `report` (an ended member reaching its `until`, spec/sync-streams.md §4). A side answers a connection's Pulls and top-bit Fetches in the order they arrive (PullReply, FetchReply or Error); a requester counts one of them still unanswered when a later one's answer arrives as skipped: a skipped Pull as refused, a skipped Fetch as answered with none of its IDs.
- **Fetch** between such nodes (spec/sync-streams.md §4, Stream), with a top-bit id: `sync_id` a member of the connection's shared set; an ID it does not hold, or of a sync ID it does not share there, is answered with none; `max_reply` and a prefix as below (Fetch).
- Between such nodes nothing else syncs: no Delete is sent.
- **Digest** (spec/sync-opens.md §3): `digest` 32 bytes. **Members**: at most 4096 sync IDs, `more` true on every page but the last; sent only after a Digest that differs. Neither is answered.
- **Resume** (spec/sync-opens.md §3): dialer to listener, after the dialer's `Proved`, at most one per connection (a second, or one before a Prove, is answered Error 2; a listener keeping no record for this connection answers Error 1). `nonce` 32 random bytes; each `tag` 32 bytes, at most `MAX_RESUME_TAGS` of them, as many as fit one message. **Resumed**: the listener's own `nonce`, and `tag` when it holds a listed record.
- **Register**: replies Ok (also when the step already is the head), or an Error without the head (spec/sync-ids.md §6):
  - 2 when the step's sync ID is not the message's or the claim set does not hash to `claims_hash`;
  - 1 for a genesis step that does not verify;
  - 13 for a child step of an unknown sync ID;
  - 9 for a step that is not a valid child of the head;
  - 12 when that genesis step does not fit a storage cap (a child step that does not fit: spec/sync-ids.md §6);
  - 4 when registrations are rate-limited;
  - 14 when the node reads the sync ID or does not sync it.
- **Stamp**: `stamp` under `"osis v1 stamp"` (`"osis v1 role entry"` for a role entry, spec/sync-ids.md §6), digest BLAKE3(canonical `[sync_id, blob_id, wrap]`).
- **Deposit item**: `sig` by the deposit key under `"osis v1 deposit"` (`"osis v1 role entry"` for a role entry), digest as for a stamp.
- **Delete**: answered Error 8 whole where the sync ID is not open on the connection (spec/sync-ids.md §6); per item, signatures under `"osis v1 delete"` over digest BLAKE3(canonical `[sync_id, blob_id, [level*]]`), the levels those of its `[level, dsig]` pairs, ascending, distinct, within 1..3:
  - with no pair, `sig` by the head's delete key;
  - else each `dsig` by that level's delete key, verifying under the commitment at that level of at least one of the blob prefix's groups (spec/crypto.md §7), every group covered by at least one pair, and `sig` by the head's write key when any level is 3, else its sync key (spec/sync-ids.md §6). A pair verifying under no group refuses the item.
  - An item whose entry is not held: by the delete key, 0 when a tombstone of the blob exists (a repeated delete is idempotent), else 1; with levels, 1 (the prefix to check them against is gone).
  - Status gives one code per item in order.
- **Events**: 0 an entry added or a deposited one stamped, its wrap and stamp replaced (no stamp: deposited), 1 deleted, 2 the sender is full for the sync ID (`full` a bool: true full, false room again; only in a Stream with no cursor, spec/sync-streams.md §4), 3 a new head (without claim set), 4 the sender refused a pulled entry for anything but room, with the refusal's code (only in a Stream with no cursor, spec/sync-streams.md §4). Expiry produces no event.
- **Fetch** (spec/sync-streams.md §4): items in request order, possibly a prefix of the request when the reply would exceed `max_reply` (in `SMALL_REPLY..=REPLY_BUDGET`), possibly none below `REPLY_BUDGET`; the requester asks the rest again under `REPLY_BUDGET`.
- **Stranded** and **Suspect** (spec/permissions.md §4): node to node only, answered Ok whatever the receiver does with them. Stranded names a sync ID the sender is stranded on and the holder (a tid) it reads the sync ID's actor through, with that holder's holder keys (§9); Suspect carries suspect entries of things in the sync ID's closure, `thing` a tid, `ak` an AK, `digest` 16 bytes, as many as fit `MAX_MESSAGE` per message.
- **Client port** (kinds 24-29): served on every connection of a node, at every listener and on those it dialed (spec/sync-transport.md §5, One key). `session_id` is 16 bytes; `secret` is exactly 32 bytes.
  - **Auth**: answered Reply `[0, []]`.
    - A main session (the unix transport, spec/sync-transport.md §6) sends Auth without `secret`.
    - A client-actor session, on a keyed transport, sends it with its bearer secret (spec/data-model.md §9), which binds the session to the client actor of the `clients^.0` entry whose `secret_hash` is its BLAKE3, compared in constant time, `until` not passed.
    - Any other Auth is answered Error 1: no matching entry, no secret on a keyed transport, a secret on the unix transport, a second Auth of a client-actor session.
    - Past `MAX_CONNS_PER_CLIENT` authenticated sessions of one client or `max_clients` of all clients: Error 4.
    - A Call or Sub before an Auth answered by Reply is answered Error 1.
  - **End of a client-actor session**: it ends when its entry goes, its `secret_hash` changes or its `until` passes. Each request is checked at the time it runs and does not run if any of those holds.
  - **A client actor's rights**: every method of a client-actor session runs as its client actor, by that actor's rights at that time.
    - A thing the actor may not read (spec/sync-judgement.md §1, and not a kept copy it reads, spec/permissions.md §3) answers every method as a thing the node does not know.
    - A write the actor may not make is code 3, adding a thing it may not read to a group code 1, a `link` value anywhere in its write code 8.
    - A revert needs the actor's rights on every write it makes (of a thing it deletes: every aspect, and its memberships in every group both the node and the actor may write; a membership in any other group stays, as for a delete) and on everything the reverted commit touched, and lists nothing the actor may not read (code 3).
    - Methods carrying state beyond a thing the actor may read are for main sessions only, code 11 otherwise.
    - This is the client's node's own rule, not a validity rule: receivers judge its commits by the author account's rights (spec/permissions.md §1), and its header's actor only by whether the author acts for it (spec/permissions.md §5.2), never by the actor's rights on what it writes.
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
    | 14 | closed: the node closed while the call was in hand | `[]` |
    | 15 | in use: the node's store is open elsewhere | `[]` |

  - **Payload**: `[0, ..]` is a delivery, `[1]` the subscription lapsed (its id is free), `[2, source]` a delivery above `max_reply`.
  - **Flow control**: spec/sync-streams.md §1; Notifies follow the push rule (spec/sync-streams.md §2).
  - **Subscriptions**: at most `MAX_SUBS` live subscriptions per connection (Error 4 past it).
- Once one signature of a message verifies under no key the receiver tries (code 1), it MAY check the message's later signatures against the head's keys only (code 1 where 9 would be due).
- Code 9 refuses a signature under an earlier key of the sync ID's role (a node answers it for some recent earlier keys, 1 past them) and carries nothing more, never the head: the signer learns the head where it opened the sync ID (a stream's head event, spec/sync-streams.md §4) and signs again once it holds a newer key.
- **Status codes**:

  | code | meaning |
  |---|---|
  | 0 | ok |
  | 1 | refused |
  | 2 | malformed |
  | 3 | too large (a relay-only blob above `MAX_RELAY_BLOB`; an oversized message is answered as malformed, 2) |
  | 4 | rate limited |
  | 5 | deposit budget full |
  | 6 | tombstoned |
  | 7 | expired |
  | 8 | not open |
  | 9 | key not of the head |
  | 11 | unsupported |
  | 12 | storage cap reached |
  | 13 | unknown sync ID |
  | 14 | refused |

- **Per-message caps**:
  - Delete: 1024 items.
  - Fetch: 1024 IDs.

## 12. Bundles
- A bundle file (spec/sync-streams.md §6) is the 8 ASCII bytes `osisbndl` followed by frames as in §11.1, each one record. The first record is `[0, 1]` (bundle format 1). Records:
  - `[1, sync_id, [[step, Opt(claim_set)]+]]`: the registration path from the genesis step to the head;
  - `[2, blob]`: blob bytes, before the first entry naming them, once per bundle;
  - `[3, sync_id, blob_id, wrap, Opt(stamp)]`: an entry (no stamp: deposited);
  - `[4, sync_id, blob_id]`: a deletion.
- Steps and claim sets are their canonical bytes as byte strings (as in §11.2). An importer verifies paths and stamps as a node keeping the sync ID unread does (spec/sync-ids.md §6) and applies the records as a peer's log events received without a cursor: a path record after the first for its sync ID must pass through the current head; an entry before its blob's record, or stamped before a path record of its sync ID (its stamp checked against that path's head), is malformed; a second format record is malformed, another bundle format parks the file; records of unknown kind are skipped.

## 13. Decoder limits
- Any object: CBOR nesting at most 512 deep, values inside it at most `MAX_VALUE_DEPTH` (spec/data-model.md §5); no array or map longer than the bytes that remain.
- Blob `MAX_BLOB`; frame `MAX_MESSAGE`; a message at most 2^20 CBOR data items in all; AK `MAX_AK_BYTES`; URL 256 bytes.
- Header: each inline list at most `CHUNK_THRESHOLD` bytes, each linked one at most `MAX_LIST_BYTES`. Prefix: 65535 groups of at most 3 commitments, within the blob. Claim set: `MAX_CLAIMS` keys; a claim set with its entry boxes is at most `MAX_MESSAGE` − 64 KiB. Tree node and link page: 512 links (a tree node one length per link); tree level 48. Sequence run: `MAX_RUN` elements, a list run's `Content` closing at `CHUNK_MAX` bytes; runs without `Content` in a writer or import delta: `MAX_DELTA_BARE` elements in all (spec/crdt.md §3.3). Link: §10. Messages: §11.2.
