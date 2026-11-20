# Wire formats
> Summary: Byte layouts of everything that leaves a node, and the table of every constant's value.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a sync ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin, 3 sync (ordered sync < read < write < admin). A purgeable-by class: 1 `admin`, 2 `author_or_admin`, 3 `writer`. A delete level: 1, 2, 3 (spec/crypto.md §7).
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
| `MAX_AK_BYTES` | 1024 bytes, one AK (§4, §12) |
| `MAX_VALUE_DEPTH` | 64 levels of nesting in a value (§12, spec/data-model.md §5) |
| `MAX_DRIFT` | 1 hour |
| `MAX_RELAY_BLOB` | 64 KiB (65 536 bytes), whole relay-only blob (spec/sync-ids.md §6; spec/sync-compaction.md §2) |
| `ROLE_KEEP` | 90 days |
| `INBOX_LIFETIME` | 90 days: the history the account's creation sets for its inbox's signals (spec/sync-inbox.md §1) |
| `DEPOSITS_WAITING`, `DEPOSITS_WAITING_BYTES` | 32 entries, 1 MiB (1 048 576 bytes): deposits a node leaves waiting under a sync ID it clears (spec/sync-inbox.md §4) |
| `LIST_TREE_DEPTH` | 32: levels of a rotation's list tree, at most 2^32 thing lists per rotation (§4, List tree; spec/permissions.md §5.5) |
| `MAX_CHAIN_DEPTH` | 64 links from a thing up its record chain to its key actor (spec/permissions.md §1) |
| `MAX_PATH_THINGS` | 64 things listed in one stated path (§4) |
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
| `MAX_ROTATIONS` | 256 account rotations in one Prove or Proved (§11.2) |
| `MAX_RESUME_TAGS` | ⌊(`MAX_MESSAGE` − 64) / 34⌋ tags in one Resume (§11.2; a tag's encoding is 34 bytes) |

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
| `SETTLE_MS` | local policy, 30 s: how long a node leaves another node's fresh demotion or `keys.0` to its signer before copying it, and a dependent thing with a holder to the signer of its newest edge write before making it independent (spec/permissions.md §2, §3, §4) |
| `PASS_WAIT_MS` | local policy, recommended 1 hour: how long a complete pass waits for a peer whose record holds the sync ID (spec/sync-status.md §1) |

## 3. Creation records and agility enums
- Agility enums (spec/crypto.md §8) are values: `signing_key = enum { ed25519 1 (blob) }` (32 bytes), `kem_key = enum { x25519_mlkem768 1 (blob) }` (`pk_x || pk_m`, 1216 bytes), `sealed = enum { x25519_mlkem768 1 (blob) }` (`ct_x || ct_m || AEAD`). Each encodes as `1617([1, h'...'])`.
- A **creation record** is the value `creation = struct { admin 0: weak, key 1: signing_key, nonce 2: blob, link 3: weak, account 4: bool, expires 5: timestamp }` holding exactly one of fields 0 and 1, and a 32-byte nonce: a thing `{0: admin, 2: nonce}` (its mint admin, spec/permissions.md §1), a link's actor K `{0: admin, 2: nonce, 3: target}` (the thing it was made for, spec/permissions.md §7), a key actor `{1: key, 2: nonce}`, an account `{1: key, 2: nonce, 4: true}` (`key` its first epoch's, spec/crypto.md §3). Fields 3 and 5 are only beside field 0; field 4 only ever true and only beside field 1; field 5 is the thing's expiry (wall ms, at most 2^63 - 1, spec/commits.md §5 Destruction), absent for a thing that does not expire. Its canonical encoding is what the tid hashes: tid = first 15 bytes of BLAKE3(canonical bytes). `created.0` holds this value (spec/data-model.md §9); a `created.0` whose read does not hash to its tid, holds not exactly one of fields 0 and 1, a field 3 not a weak or beside field 1, a field 4 not `true` or beside field 0, a field 5 beside field 1, or any field other than 0 to 5, is bad input (a closed struct, not parked); an unknown `signing_key` case parks the thing (spec/versioning.md §2).
- A link key's nonce is `kdf("creation nonce", seed, "")`; an account's is `kdf("first device", first seed, creation device's tid)` (spec/crypto.md §3); a node's is random.
- **Record blob** (spec/permissions.md §4): a blob whose plaintext, in place of a `CommitBlobPlaintext`, is `RecordBlobPlaintext := ["records", [creation+]]`, the creation records ascending by tid, distinct, each read as `created.0` reads one; durable, with no expiry and one commitment group of one level-3 commitment (spec/crypto.md §7 Certificate blobs). A reader takes each record's tid from its hash: a record needs no signature. Anything else is bad input.

## 4. Commits
```
Header    := [version, signer, path, kind, ts, form, expires, aspects,
              purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation, reseal, remains, flags?]
Path      := [index, tid*]                 ; the purge-author index, then the listed things A1..Ak
Paths     := Path | [hash, hash+]          ; one Path for every thing written, or one hash per thing
Salted    := [salt, Path]
Aspect    := [tid, ak, lo, hi, Retention, keys, hash, replaces]   ; replaces := [] | [commit_id] | [commit_id, floor]
Retention := by
DeleteKey := [level, pk]
PurgeItem := [tid, ak] | [tid, ak, author] | [tid, ak, ts, source]
Rotation  := [signing_key, kem_key, [epoch_id+], [commit_id*], [commit_id*], bool, bytes, list_root, [SeedBox*]]   ; supersedes, names, takes, revokes, devices
SeedBox   := [tag, sealed]
Reseal    := [signing_key, [SeedBox+]]
CommitBlobPlaintext := [Header, signature, Opt(inner), [signature*], [Section*]]
Section   := [[ai+], [chain*], wrap, ciphertext]
Contents  := [Opt(Salted), [Part*]]
Part      := [ai, delta]
```
Header fields by position:
0. `version`: uint, the format version (1).
1. `signer`: tid of the key actor whose key signs the commit (spec/permissions.md §1): an account, or a key actor other than an account signing as itself (a node only for its own node thing's aspects, spec/permissions.md §1). The commit is by its signer (spec/commits.md §1).
2. `path`: the paths the commit states, one per thing it writes (spec/permissions.md §5.2), as `Paths`:
   - A `Path` is `[i, A1, …, Ak]`: the purge-author index i (a uint, i ≤ k: 0 names the signer, j the thing Aj, spec/permissions.md §6) then the 15-byte tids of the listed things in order, 0 ≤ k ≤ `MAX_PATH_THINGS`, no tid twice and none equal to `signer`. The empty path naming the signer is `[0]`.
   - **One path**: where every thing the commit writes is written along the same path, `path` is that `Path`, stated once for all; a writer MUST use this form then.
   - **Hashed**: where the paths of the n ≥ 2 distinct tids `aspects` names differ, `path` is n 32-byte hashes, one per tid in the order `aspects` lists them; the hash of thing T's is `kdf("path", salt, canonical bytes of T's Path)` with a 16-byte `salt` the writer draws at random per thing; T's sections carry the salt and the Path (`Section`, below). The hashes are always inline, outside Inline or link: a reader needs them before it opens any section, and they are bounded by the things the commit writes (34 bytes each, §12).
   - A decoder accepts the one-path form for any number of things (it cannot check that the things' paths were equal without opening every section). Bad input: a hashed `path` on a commit writing one thing, a hash count other than n, or a `Path` with i > k, k > `MAX_PATH_THINGS`, a tid twice or a tid equal to `signer`.
   - A rotation (field 15) and a seed re-seal (field 16) state `[0]`: the signer writing itself. A commit carrying a purge request (field 8) states one path; a hashed `path` beside one is bad input (spec/permissions.md §6).
3. `kind`: 0 content, 1 role, 2 content compaction snapshot, 3 role compaction snapshot (spec/commits.md §2).
4. `ts` (spec/crdt.md §2.2). 5. `form`: 0 commit form, or `[1, nonce]` session form with the session's 16-byte nonce (spec/commits.md §3).
6. `expires`: `Opt(T)`, the commit's expiry, wall ms (spec/commits.md §6).
7. `aspects`: `[Aspect+]` sorted by the canonical bytes of `[tid, ak]`, distinct.
8. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`; `[tid, ak, author]` those of them whose purge author is `author` (spec/permissions.md §6); `[tid, ak, ts, source]` the delta on that aspect of the commit stamped `ts` whose own writes are `source`'s (spec/crdt.md §2.1: 31 bytes, a session; 32, a commit-form commit's ID; else bad input), one commit per stamp and source on an aspect (spec/commits.md §5 Purge); on `created.0` only `[tid, created.0]` (it names every minting, spec/commits.md §5 Destruction).
9. `undoes`: `Opt(commit_id)`.
10. `blind`: 16 random bytes (spec/crypto.md §7).
11. `keys`: `[DeleteKey*]` sorted by canonical bytes, distinct: the delete keys of the commit's deltas (spec/crypto.md §7), `pk` a valid Ed25519 key (§1, spec/crypto.md §1), at level 2 one per distinct purge author of a delta whose retention calls for level 2; a key no aspect lists is bad input.
12. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9), exactly `{0: set<32-byte commit ID>}`, inline or linked; present iff the commit is a role commit carrying an explicit removal or a lowering (spec/permissions.md §5.1 Frontier; a writer rule: a receiver checks only that it sits on a role commit). Any other value there is bad input.
13. `ephemeral`: `Opt(uint)`, the ephemeral marker (spec/commits.md §2): 0 an ephemeral commit, 1 a relay-only one. Present only with `kind` 2 and `form` 0, or `kind` 0, no `purge`, no list by link and no `created.0` aspect; every aspect's retention is `writer`, with the levels it calls for; a relay-only commit is of `kind` 2 with no `expires` and no `undoes`, and a delta of it linking a page is bad input (its deltas never page, spec/commits.md §2). Anything else is bad input.
14. `epoch`: `Opt(epoch_id)`, the epoch an account signer signs at (spec/crypto.md §9; 32 bytes: the minting plain rotation's commit ID, a merge's ID, 32 zero bytes for the first epoch); present iff the signer's creation record marks an account, else bad input.
15. `rotation`: `Opt(Rotation)`, present only on a role commit whose signer is an account (else bad input): the new epoch's signing key and KEM key (spec/crypto.md §3); the epochs it supersedes, ascending, distinct, the header's `epoch` among them (else bad input); `path` the one-for-all `[0]` and a `keys.0` delta on the signer (else bad input); the tips it names (a merge certificate, spec/crypto.md §9 Merges: every tip but the header's `epoch`; empty for a plain rotation), ascending, distinct; a merge certificate supersedes exactly the header's `epoch` and its names, takes nothing, and has `revokes` false and `devices` empty (else bad input); the rotations it **takes** (spec/permissions.md §5.4: carrying removals from D its maker took, not on its line; every node holds the rotation only once these are, and only the account's nodes read it further), ascending, distinct; `revokes`, whether it removes a device from D (spec/permissions.md §5.5 Revoked: what every reader reads of its membership changes); `devices`, its membership changes of D sealed (spec/crypto.md §9, Roster), empty when it carries none; `list_root`, 32 bytes, the root of its list tree (below); its seed boxes (spec/crypto.md §9, Custody), each a 16-byte `tag` and a sealed box (§7) of a payload of 32-byte seeds, at least one, ascending by tag, distinct (else bad input). A plain rotation's commit ID names the epoch it mints; a merge certificate's epoch is its merge ID.
16. `reseal`: `Opt(Reseal)`, a seed re-seal (spec/crypto.md §9, Custody), present only on a role commit whose signer is an account, `path` the one-for-all `[0]`, whose `rotation` is absent (else bad input): the signing key of the epoch whose seed it boxes and its seed boxes, as `rotation`'s, at least one, ascending by tag, distinct (else bad input).
17. `remains`: `Opt(tid)`, the holder of the remaining admin edge the commit's edge writes rely on (spec/permissions.md §1, The last admin); present only with `kind` 1, an aspect `roles.0` in `aspects`, and the adminless bit (field 18) clear; else bad input.
18. `flags`: uint, present only when nonzero. Bit 0, own cover: its writer's own cover at a removal or an account's rotation (spec/permissions.md §5.1, §5.5, Own cover), only with `kind` 2 and no `ephemeral`. Bit 1, adminless: the adminless mark (spec/permissions.md §2), only with `kind` 1. Other bits are reserved and MUST be zero. A `flags` of 0, a reserved bit, or a bit on a header it is not allowed on is bad input.

Aspect fields: `tid`; `ak` (text, spec/data-model.md §2, at most `MAX_AK_BYTES`); `lo`, `hi`: the counter range (`lo = hi = 0` for kinds 2, 3; else `1 <= lo < hi`); `Retention`: `by`, the purgeable-by class (spec/commits.md §5); `keys`: `[ki*]`, ascending indices into the header's `keys`: one per level the retention calls for (spec/crypto.md §7), exactly those levels, else bad input; `hash`: the 32-byte delta hash of its one delta. `replaces`: `[]`, `[commit_id]` or `[commit_id, floor]` (`floor` ≥ 1; a floor of 0 is the second form, else bad input), the fire the delta claims to replace and that fire's floor (spec/commits.md §5 Signals), allowed only on a durable signal's delta of a durable commit; anywhere else the part is bad (spec/commits.md §2).

- **Inline or link**: `aspects`, `purge`, `keys` and the frontier (not `path`, field 2) are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the header's **list key** `kdf("header list", dedup secret of the header's signer, skeleton)`, the skeleton being the header's canonical bytes with each position that goes by link holding `[]` (so a list's tree serves one header only). A decoder rejects an inline list above the threshold or a link to one at or below it or above `MAX_LIST_BYTES`; a writer refuses such a commit. Header-list chunks carry the commitments of §5: every link of a list's tree names no delete key (an empty group, spec/crypto.md §7); any other is bad input.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the signer's key (an account's: the signing key of the epoch the header names) under `"osis v1 commit"` over the digest below. The commit ID covers `signer` and `path`; where `path` is hashed, each thing's `Path` is bound by its hash there and its `Salted` sits in ciphertext whose AD is the commit ID.
- The commit signature of an account signer's commit signs BLAKE3(commit ID ‖ `inner` ‖ each merge signature) (spec/crypto.md §2); every other commit's signs the commit ID.
- **Inner signature** (spec/crypto.md §3): `inner` is present iff the signer is an account (else bad input): one or more seals of 95 bytes each, concatenated, each XChaCha20-Poly1305 under `kdf("inner key", inner secret, commit ID)` of one epoch, nonce 24 zero bytes, no AD, of the node's tid (15) then its raw Ed25519 signature under `"osis v1 inner"` over the commit ID (64). The first is under the epoch the commit is signed at; a commit carrying a `rotation` has one more per epoch it opens with, in order: a plain rotation's, the epoch it mints; a merge certificate's, each tip it names in that order, then the merge epoch. Another count is bad input.
- **Merge signatures**: one `signature` per tip the header's `rotation` names, in that order, each under `"osis v1 merge"` over the merge's ID by that tip's signing key (spec/crypto.md §9); empty without a rotation; another count is bad input. A header-only copy of a rotation (spec/sync-judgement.md §1) carries them.
- **List tree** (spec/permissions.md §5.5): a binary Merkle tree of depth `LIST_TREE_DEPTH` whose leaves are a rotation's thing lists, each at a random distinct index below 2^`LIST_TREE_DEPTH`.
  ```
  ThingList := [tid, [commit_id*] | LINK, salt]
  ThingCert := [rotation_id, index, [hash*], ThingList]
  ListBlobPlaintext := ["list", [ThingCert+]]
  ```
  - `ThingList`: the thing, the commit IDs ascending and distinct (inline iff its canonical encoding is at most `CHUNK_THRESHOLD`, else a LINK to a chunk tree of it as for a linked frontier, keyed by the thing's dedup secret), a fresh random 16-byte `salt`.
  - Leaf = BLAKE3(`"osis v1 list leaf"` || canonical bytes of the `ThingList`); an interior node = BLAKE3(`"osis v1 list node"` || left || right). Every subtree holding no leaf hashes to a fresh random 32-byte value. `list_root` is the root.
  - `ThingCert`: the rotation's commit ID, the leaf's index (uint), the `LIST_TREE_DEPTH` sibling hashes from the leaf up; it verifies when folding the leaf with them by the index's bits (bit k set: the sibling is on the left at height k) gives the rotation's `list_root`. A cert that does not verify is bad input.
  - A list blob (spec/sync-judgement.md §1) is a blob whose plaintext, in place of a `CommitBlobPlaintext`, is `ListBlobPlaintext`, its prefix as a record blob's (§3).
- **Commit blob** plaintext: `CommitBlobPlaintext`: one blob carries the whole commit, every part sealed to its thing's readers (spec/sync-judgement.md §1).
  - A `Section` holds the parts of one thing: `[ai+]` the aspect indices of its parts, ascending, distinct, each with a part inside; `[chain*]` the thing's derivation chain (spec/crypto.md §3) as the writer knows it, nearest first (empty for an independent thing or a key actor; at most `MAX_CHAIN_DEPTH`, no tid twice: else bad input); `ciphertext` = XChaCha20-Poly1305 of the canonical `Contents` under a fresh random 32-byte section key, nonce 24 zero bytes (the key encrypts this one plaintext and nothing else), AD = the commit ID; `wrap` = a random 24-byte nonce `||` XChaCha20-Poly1305 of the section key under `kdf("section", read secret of the thing)` (its own, or derived from its mint admin's by tid, spec/crypto.md §3) at the newest epoch the writer holds (a section of a commit giving read epochs under an epoch they supersede, spec/crypto.md §5), that nonce, AD = the commit ID: 72 bytes. A thing's role parts (`roles.0`, `keys.0`, `secrets.0`, `vouches.0`) go in a section of their own whose `wrap` is under `kdf("section", roles secret)` of that epoch (spec/crypto.md §4, Roles secrets). Sections sorted by their first `ai`; an aspect in two sections is bad input; zero sections is allowed (every delta purged). A copy (per-sync-ID or certificate, spec/sync-judgement.md §1) holds its parts in one section (one per thing where `path` is hashed, each carrying its thing's `Salted`), each with an empty chain, its `wrap` under `kdf("section", blob key)` in place of a read secret: whoever opens a wrap of the blob reads it.
  - `Contents` holds the thing's `Salted` iff `path` is hashed; every section of a thing (its role section and its other section alike, and each copy of its parts) carries the same `Salted`. A section whose `Salted` is absent where `path` is hashed, present where it is one path, does not hash to its thing's entry in `path`, or sits beside parts of another thing, holds no part of the commit: its parts are as bytes that do not match the header's delta hash (spec/commits.md §4).
  - A reader tries, per section, the read secrets it holds of the section's thing, those derived by tid through the listed chain from the epochs it holds of any member of it (the thing's record may be inside the section; a member made independent since holds the derived epoch in its history), newest first, and the blob key. Parts that open on an aspect the section does not list, or a listed aspect with no part, are bad input. A section no held secret opens is kept as it is: a non-reader learns nothing of it beyond its size, `ai` list and chain, and copies it verbatim into a fresh encryption of the commit.
  - A `Part` holds one delta: `ai` indexes `aspects`, `delta` is the embedded `Delta` or `Snapshot` array (spec/crdt.md §3.2, §8) whose canonical bytes hash to that aspect's `hash`. Within a section parts sorted by `ai`, distinct.
  - The blob's prefix commitment groups are those of the delete keys its sections' aspects list (§5); its expiry is the header's `expires` (exceptions: §5). The whole commit stays within `MAX_BLOB` (a writer pages its deltas, spec/crdt.md §8, and refuses a commit that still does not fit): about 150 000 small changes on one thing, or about 6 500 things.
- A header violating a rule of spec/commits.md §2, §5 or §6 is bad input:
  - an aspect of the wrong class for its kind (`created.0` fits either kind);
  - `created.0` in a kind without own writes or with the ephemeral marker;
  - a role compaction snapshot of `roles.0`;
  - a role-class, `addenda.0`, `retention^.0` or `purge.0` aspect whose retention is not its fixed one (spec/commits.md §5);
  - `expires` on a commit with such an aspect;
  - a content compaction snapshot's delta without fixed retention whose `by` is not writer;
  - `expires` or a purge item on a role commit;
  - a purge item naming a role-class aspect;
  - a purge item on `created.0` by commit or by author;
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
- Plaintext per blob kind: commit blob `CommitBlobPlaintext` (§4); chunk: the raw chunk bytes; tree node and link page: §6; page: §6; sealed fire: §9 (its ciphertext is a sealed box, not the AEAD above).
- Class: a commit blob's class is that of its header's ephemeral marker (none: durable, 0: ephemeral, 1: relay-only); a mismatch is bad input. Sealed fires take their commit's class; a chunk, tree node, page or link page has the class of the commit whose delta introduced it. A commit blob's expiry `T`: none for a header-only blob (no section); else a relay-only commit's header `ts` (wall ms) plus `MAX_DRIFT` (its header carries no `expires`), any other commit's header `expires`; any other is bad input.
- Commitments, blinded by the blob's own salt and its blind (a commit blob: its header's; a chunk, tree node, page or link page: its thing blind), one per level within a group (spec/crypto.md §7):
  - a commit blob carries one group per distinct delete-key set among the aspects its sections list (opened or not; a sealed fire: the aspects its commit lists), each group the keys of that set in header key order, groups in order of their first aspect; a header-only blob carries no group;
  - a chunk, tree node or page carries one group: the delete keys of the delta that created it;
  - a chunk or tree node of a linked header list (§4) carries one empty group (spec/crypto.md §7; spec/sync-ids.md §6 Delete: it goes by the delete key or at its expiry); its expiry is the commit's `expires`.
- **Wrap**: XChaCha20-Poly1305 under `kdf("wrap", read secret)` (the read secret of the sync ID's thing), nonce = first 24 bytes of the blob ID, empty AD, plaintext `suite (1) || blob key (32) || order (8, little-endian)`: 57 bytes. A filler is 57 random bytes.
- A node that does not know a blob's framing version stores and relays it as a durable blob with no expiry and no commitments.

## 6. Chunker, chunk trees, pages
- **Gear table**: `G[i]` (i = 0..255) is the little-endian u64 at bytes `8i..8i+8` of the 2048-byte BLAKE3 XOF output of the ASCII string `"osis v1 gear table"` (unkeyed).
- **Chunker** over a byte sequence: at each chunk start `h = 0`; for each byte b, `h = (h << 1) + G[b]` (mod 2^64), and the chunk ends after that byte if its length is at least `CHUNK_MIN` and `h >> 48 = 0`, or its length is `CHUNK_MAX`. The last chunk ends at the end of the sequence.
- **Chunk tree** of a large atomic value (spec/data-model.md §6) or a linked header list or frontier (§4): the leaves are the chunks of its canonical bytes. Level 1 groups the leaf links in order into nodes; a node closes after a link when it holds at least 2 links and the link's content hash begins with byte `0x00`, or when it holds 512 links; the last node closes at the end. If a level yields one node, that node is the root; else the links to its nodes are grouped the same way into level + 1. The root is always an interior node, even over one chunk.
- A tree node's plaintext is `[level, [LINK+], [len+]]`: level 1 nodes link chunks, level k nodes link level k−1 nodes. Levels are at most 48. `len` (uint) has one entry per link, in link order: the byte length of the plaintext under that link (a chunk's length at level 1, the sum of a child node's lengths above). A node whose lengths overflow u64, or a level-k node with a length above `512^(k−1) · CHUNK_MAX` (at level 1: a chunk above `CHUNK_MAX`), is bad input.
- **Link content hash** (spec/crypto.md §6), keyed by the dedup secret (a header list's: its list key, §4): of a chunk, `kdf("link", d, chunk bytes)`; of a page or link page, `kdf("link", d, plaintext)`; of a tree node, `kdf("link tree", d, le64(level) || for each link in order: its content hash || le64(its len))`. The root's content hash identifies the value. A reader verifies the content hash of every link it resolves; a mismatch is bad input.
- **Lengths** are the writer's claims: a reader checks every one it resolves a link through (a child node's lengths sum to its length in the parent, a chunk is exactly its length) and treats a mismatch as bad input; it never sizes a buffer from a stated length. A reader may pass a subtree by its length without fetching it (a seek fetches the root and the nodes on the path to the target chunk).
- **Tree reader bounds**: a chunk other than the last that is empty or shorter than `CHUNK_MIN` is bad input. A reader accepting at most `max_len` bytes of a value visits at most `max_len / CHUNK_MIN + 1` chunks, and a tree needing more is too large.
- **Pages** (spec/crdt.md §8): the gear hash runs over the concatenated canonical encodings of the array's elements (of a field map: each field's key then value), `h = 0` at each page start and never reset inside a page; a page closes after the first element at one of whose bytes the page length is at least `CHUNK_MIN` with `h >> 48 = 0`, or at whose end the page holds `CHUNK_MAX` bytes or more; the last page closes at the end of the array. A page's plaintext is the canonical array of its elements (of a field map: the canonical map of its fields). The links to the pages are level 0. While a level's `[LINK+]` would exceed `PAGE_TARGET` bytes and holds two links or more, its links are grouped in order into link pages by the tree-node rule (a group closes after a link when it holds at least 2 links and the link's content hash begins with byte `0x00`, or when it holds 512 links; the last closes at the end), each a blob with plaintext `[LINK+]`, and the links to those link pages are the next level. The fragment holds the first level that fits or holds one link. So every leaf page lies at the same depth; a reader refuses leaf pages at two depths, a link page above 512 links, and any tree other than the one these rules give its leaf pages (spec/crdt.md §3.3, re-encoding). The depth has no bound but the pages: each level is pages the author delivered, at most about log2 of the leaf pages.

## 7. Boxes
- A sealed box (spec/crypto.md §1) is `ct_x (32) || ct_m (1088) || AEAD_K(nonce 24 zero bytes, AD, payload)`, held in a `sealed` value (§3).
- **`secrets.0` box** (spec/crypto.md §4), a `box` value (spec/data-model.md §9) keyed by `box_key`. AD = `[actor, holder, role, n, nonce, form]` with the key's epoch `[n, nonce]` and `form` = `[0, Opt([kn, knonce]), suite]` for the sealed form (the recipient keyset epoch, none for a key actor other than an account; an account's epoch name, spec/crypto.md §3, for an account) or `[1, [sn, snonce]]` for the symmetric form (the epoch of s) or `[2, [[kn, knonce]+], suite]` for the joint form (its keysets, ascending).
  - Sealed payload: `[role, n, secret]`, secret 32 bytes, naming the epoch (n, nonce of the secret under the thing's tid and the role, spec/crypto.md §4); a `secrets.0` box's names its key's (role, epoch).
  - Joint: the sealed payload sealed to the last keyset's KEM key, that sealed box sealed to the one before's, and so on to the first's, each under the box's one AD.
  - Symmetric `wrap`: XChaCha20-Poly1305 under `kdf("box", s)`, nonce = first 24 bytes of BLAKE3(AD), plaintext `suite (1) || secret (32)`: 49 bytes.
  - For an account holder, `[sn, snonce]` of the symmetric form is its epoch name (spec/crypto.md §3), `s` its role secret at that epoch.
- **Entry box** (spec/sync-ids.md §2): a `box` value in the sealed form with no keyset epoch, AD = `[sync_id, step_key, form]`, payload `[role, n, secret, earlier, sync]` with the read role, `earlier` `[n, secret]` of the earlier read epoch (spec/sync-ids.md §2) or `[]`, `sync` `[n, secret]` of the sync epoch whose key the step registers; its epochs are the sync ID's thing's. A claim set holding a box of another form is malformed.
- **Superseded list** (spec/crypto.md §4): a keyset's field 4 `supersedes` (spec/data-model.md §9), `set<epoch>`: each epoch `[n, nonce]` the rotation lists. A rotation commit writes the whole keyset (a replace), so the list is read from its `keys.0` delta.
- **Left out** (spec/crypto.md §4, Holder actors): a keyset's field 6 `left_out`, `map<weak, set<epoch>>`: per holder actor M the rotation left out of the keyset's role, the epochs `[n, nonce]` of M's keysets of that role it records M left out at; empty for every other rotation.
- **Box records** (spec/crypto.md §4, Stale): `keys.0` field 8 `sealed`, `map<box_key, set<epoch>>` (reader default empty): per box of the thing to a holder actor (an account or a thing other than a key actor), keyed by that box's `box_key`, the epochs `[n, nonce]` of the holder's keysets the box names (each, for a joint box). Put in the commit that writes the box, as the box is (remove + put, or a put alone where the box is: an invite grant); removed with the box. An entry needs the role its key names, as the box (spec/permissions.md §3).
- **Carried demotions** (spec/crypto.md §4): a keyset's field 7 `demotions`, `set<blob>`: the 32-byte IDs of the other commits whose demotions it carries, and field 8 `demotes`, a bool: whether its own rotation commit is one. Every keyset a rotation writes carries the same.
- **Names digest** (spec/crypto.md §4): a keyset's field 5 `names`, 32 bytes: the unkeyed BLAKE3 of the canonical bytes of the rotation's names as the history box carries them (`[[name*], Opt([ts, signer, blind])]`, below).
- **History box** (role r, epoch e): XChaCha20-Poly1305 under `kdf("history", secret_r[e])`, nonce 24 zero bytes, AD = `[actor, role, n, nonce]`, plaintext `[[[n, secret]*], [[name*], Opt([ts, signer, blind])], floor, [[n, roles secret]*]]`: the earlier secrets strictly ascending by the epochs they name (by `n`, then `nonce` bytewise), each `n` below e's (a box breaking this opens to nothing), then the names (spec/crypto.md §4), each `[ts, signer, commit, holder, void]` (the edge write's commit key, the holder whose edge it writes, and whether it is void, a bool), ascending by those fields, then the departs mark (the rotation commit's `ts`, signer and header `blind`), then the epoch's floor, a uint (spec/crypto.md §4 Floors; 0 at a role other than read), then the roles secrets of earlier epochs whose secret it does not carry, ordered and bounded alike, each naming its epoch by the nonce rule (spec/crypto.md §4); the `secrets.0` history map holds the ciphertext.
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

## 9. Sealed fires and holder keys
- **Sealed fire** (spec/crypto.md §5, spec/sync-inbox.md §2): the prefix of its commit's encryption (§5: its `expires`, the commitments of the delete keys its header lists), then the raw bytes of a sealed box (§7, not a `sealed` value) to the fired thing's read keyset KEM key the sender chose.
- AD = `[thing, "fire", n, nonce, prefix bytes]` (`"fire"` a text string), `[n, nonce]` the read epoch of that keyset.
- Payload: the padded (§5) canonical bytes of `SealedFire := [CommitBlobPlaintext, [CommitBlobPlaintext*], [creation*]]`: the fire's commit (§4); its author's chain certificates for its actor (spec/permissions.md §4), each projected to its chain deltas (an account's rotations as header-only copies); their creation records, ascending by tid, distinct.
- A receiver ingests the chain before the commit, and only its records and accounts' rotations.
- **Holder keys**: `HolderKeys := [CommitBlobPlaintext*], [creation*]`: the holder's current `keys.0` commits (spec/permissions.md §4), each projected to its `keys.0` delta on the holder, with their authors' chain certificates for those deltas, each projected to its chain deltas (as the chain of a `SealedFire`); then that chain's creation records, ascending by tid, distinct. A receiver ingests only what is on things in the holder's authority chain as it judges it while taking them (spec/permissions.md §4): `keys.0` deltas on the named holder and on the authors of the holder's `keys.0` commits carried (their cards), records, and `roles.0` deltas, each kept only if judged valid; it ignores the rest.

## 10. Links
```
Link := [1, seed, target, k, k_sync_id, [peer*], ? flags]
peer := [dialable, [url*]]
```
- `Link` (spec/permissions.md §7): format 1, L's 32-byte seed, the target tid, K's tid, K's sync ID, and the nodes to dial for first contact, each a `dialable` 32-byte key and the transport `url`s it is dialed at (as `dial^.0` gives them, spec/data-model.md §9): first the sharer node, its dialable key with one `peer://` URL of its relays (the relay items of `reach.0`, spec/data-model.md §9, spec/sync-transport.md §3, in order, those that would take the URL past 256 bytes left out; no relay: `peer://`), then each of the sharer node's configured addresses (spec/sync-opens.md §1) of another key, in order, its key with its URL, while there is room. The redeemer dials each peer, its first URL first; one holding K's sync ID serves it as at any peer (spec/permissions.md §7). `flags` (uint): bit 0 single use (the redemption removes L's own grant, spec/permissions.md §7); other bits are reserved and MUST be zero; present only when nonzero (a link with `flags` 0 or a reserved bit set is malformed).
- The sync ID a link names is K's sync ID (spec/sync-ids.md §2): K is created with it.
- Caps: at most 4 peers, 4 URLs per peer; URLs at most 256 bytes (§12).
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
Fetch     [19, id, max_reply, [[sync_id, [blob_id+]]+]] -> FetchReply [20, id, [[blob_id, Opt([blob, wrap, Opt(stamp)])]*]]
Auth      [24, id, Opt(secret), session_id]      -> Reply [0, []] | Error
Call      [25, id, max_reply, method, [arg*]]  -> Reply | Error
Reply     [26, id, outcome]
Sub       [27, id, max_reply, filter]          -> Reply | Error
Unsub     [28, id, sub_id]                     -> Ok
Notify    [29, 0, sub_id, payload]
Stranded  [30, id, sync_id, holder, HolderKeys] -> Ok
Suspect   [31, id, sync_id, [suspect+]]       -> Ok
Prove     [32, id, [actor_proof*], Opt([rotation*])]  -> Proved | Error
Proved    [33, id, [actor_proof*], Opt([rotation*])]
Resume    [34, id, nonce, [tag*]]             -> Resumed | Error
Resumed   [35, id, nonce, Opt(tag)]
Beacons   [36, id, generation, Opt(base), f, lo, hi, gcs, more]  -> Shared
Offer     [37, id, [item+]]                    -> Shared
Lost      [38, id, [[sync_id, Opt(cursor)]+]]  -> Shared
Shared    [39, id, [[code, Opt(tag), Opt(grant), Opt(sig), unread]+]]
NoRecord  [40, id]                             -> Shared
Pull      [41, id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral]
                                               -> PullReply [42, id, [[sync_id, event]*], Opt(cursor), whole, trimmed, more, report, [join*]]
Stream    [43, 0, [[sync_id, event]*], Opt(cursor), report, seq]
Applied   [44, 0, cursor]
Digest    [45, 0, digest]
Members   [46, 0, [sync_id*], more]
Twin      [47, id, tag]                       -> Twinned
Twinned   [48, id, Opt(tag)]

actor_proof := [creation, key, sig]
rotation := CommitBlobPlaintext
item   := [0, hit, Opt(sig), unread] | [1, sync_id, [hit*], unread] | [2, sync_id, blob, wrap, sig] | [3, sync_id, Opt(step_id), key, sig] | [4, hit, signing_pk, sig, unread]
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

- **Prove** (spec/sync-opens.md §2, Connection proofs): dialer to listener, at most one per connection (a second is answered Error 2). `creation` is the proving key actor's creation record (§3): the key actor is its tid. `key` the signing key that made `sig`: the record's own, or for an account its signing key at an epoch (open at the verifier, spec/sync-opens.md §2). `sig` by `key` under `"osis v1 connection proof"`, digest BLAKE3(canonical `[by_listener, challenge, listener_key]`): `by_listener` 0 for a dialer's proof and 1 for a listener's, `challenge` the verifier's Hello challenge, `listener_key` the listener's static key. A verifier checks proofs in order and stops at the first that does not verify: it and those after it prove nothing, those before it stand. A message carries at most `MAX_PROOFS` proofs; past it it is refused whole. `rotation`s are the proving account's signed rotations the verifier may lack (spec/sync-opens.md §2), which ones the prover's choice, each a header-only copy (§4, no sections; one with a section is malformed), at most `MAX_ROTATIONS`, past which the message is refused whole; absent when no account is proved. A node sends its own proof first (only to a node of its own account, spec/sync-opens.md §2), then its account's, then its key actors by ascending tid, as many as fit. **Proved** carries the listener's proofs, possibly none, and its account's rotations, under the same rules. A node serving no identity answers none. A dialer whose Prove is answered Error closes the connection.
- **Beacons** (spec/sync-opens.md §5): one page of generation `generation` of a side's filter: a Golomb-Rice coded multiset of `f`-bit values over `[lo, hi)`, Rice parameter 8, each value's gap from the last (from `lo` first) as a unary quotient of 1-bits, a 0-bit and 8 remainder bits, most significant first, the last byte padded with fewer than 8 zero bits. `more` is true on every page but the last; pages are consecutive from `lo` 0 to `hi` `2^f`. `base` absent: a whole filter, `f` is `ceil(log2(n)) + 8` of its n entries (n = 0: 8); present: additions to generation `base` (or to a later one the receiver holds, spec/sync-opens.md §5), at the same `f`, at most the whole filter's n entries in all. A filter past 2^22 entries, a page out of order, a gap past `hi`, or a width or additions count breaking this against `base` itself is answered Error 2 and closes the connection. Shared answers each page, its code 0, or 13 for a `base` not held.
- **Offer**: `hit` 32 bytes, at most 1024 items and 256 hits in an item. A Hit's `sig` is the proof of a sync key's or a claim's credential (spec/sync-opens.md §4): an **open signature** under `"osis v1 sync open"`, digest BLAKE3(canonical `[side, sync_id, challenge, static_key]`) with `side` its signer's (0 the dialer, 1 the listener), the other side's Hello challenge and the listener's static key; absent for other credentials (a read secret's or a sync-key proof's Hit proves its secret itself). A Static item (`[4, ...]`) is a Hit on a key actor's static entry carrying the key actor's signing key and an open signature by it, digest as for a Hit's; it opens only where that key's static entry is the credential hit. `unread` (a bool) in a Hit, ByRole or Static item is true when its sender keeps the sync ID unread (its class, spec/sync-opens.md §4 Source). A Behind item (`[3, ...]`, spec/sync-ids.md §6) carries a credential key `key` of the step it names (a sync key, a claim, or a key actor's signing key; naming none, a sync key or a key actor's signing key) and an open signature by it, digest as for a Hit's. A Deposit item (`[2, ...]`, spec/sync-inbox.md §3) carries a durable or ephemeral blob (`blob`, `wrap`, `sig` by the deposit key, below: Deposit item), at most `MAX_BLOB`; the Offer as a whole fits `MAX_MESSAGE`. Shared gives one code per item in order, a 32-byte tag for a Hit accepted, none for a ByRole or Deposit; `unread`, for a Hit, Static or ByRole item accepted, true when the replier keeps the sync ID unread, false in every other answer; for a Hit accepted on a sync key, a claim or a static entry also `sig`, an open signature (digest as for a Hit's, with the replier's side) by the sync key of the replier's step (spec/sync-opens.md §5), absent otherwise; code 14 refuses one, for no stated reason; a Deposit item is answered 0 (taken), 14, or 4, 5 or 12 (refused for now). A Hit accepted on a static entry also carries `grant` when the answering side holds the head's claim set: the head's `entry_box` for that entry and the sync ID's path from its genesis step to that head (without claim sets). A Behind item is answered 0 with `grant` carrying no `entry_box` and the steps after the named one through the first under another sync key (without claim sets), or, by a key actor's signing key naming no step, 0 with `grant` as a Static item's accepted Hit carries; 13 for a sync ID not kept there; 4 past the Offer's step bound (spec/sync-ids.md §6: ⌊`REPLY_BUDGET` / 326⌋ steps, 326 bytes a step's greatest encoding as a byte string); else 14, with nothing; no other answer carries one.
- **Lost**: at most 1024 items, `cursor` at most 256 bytes: where the member stopped for the receiver (spec/sync-opens.md §6). Shared answers 0 per item.
- **NoRecord** (spec/sync-opens.md §3): from a dialer that keeps no record for this listener; id `2^31`. Shared answers it with one item, code 0.
- **Shared-set request ids**: `id`s of Beacons, Offer, Lost, NoRecord, Pull and Fetch (every Fetch fetches stream bodies) are chosen by each side with its top bit set, so they cannot equal an id of that side's other requests. An Error or FetchReply with such an id answers that request. A side keeping no shared set on the connection (a listener before the dialer's NoRecord or a record) answers each of them Error 14.
- **Pull** (spec/sync-streams.md §4, Stream), between two nodes that read the sync IDs they share, and from a reader to a peer that cannot read them: a `cursor` (here and in `join`, PullReply, Stream and Applied) is at most 256 opaque bytes the answering node sealed; `max_reply`, in `SMALL_REPLY..=REPLY_BUDGET`, bounds the reply's frame body: a server ends the page before an event that would pass it, so a reply asked below `REPLY_BUDGET` may hold no event, and one asked at `REPLY_BUDGET` holds at least one. PullReply carries, in log order, the events after `cursor` of each member of the connection's shared set, and of each `join`'s member after the join's cursor (from the start of the log when it has none); with no `cursor`, or any cursor of the Pull (its own or a join's) that names no position of the server's log, every member from the start, `whole` true, joins ignored; also so when any cursor of the Pull names a position below the server's deletion horizon (spec/sync-streams.md §3), with `trimmed` true. Its `cursor` is the position the reply covers for the stream; its `join` list names each join not at that position: one still in pages, with its own cursor, to name again in the next Pull, or one the server does not share, with none. `more` true: pull again from the returned cursors. `ephemeral` true: the reply also lists the live entries of the ephemeral class of every member; every join lists its member's. Ephemeral entries count against `max_reply` with the rest; what does not fit follows in later replies or Streams. `follow` true asks for pushes (spec/sync-streams.md §4 Pushes). A Stream's `seq` is the number of Streams with a cursor the server sent on the connection since its last PullReply (0 in one without a cursor). `report` asks for Applied, naming the message's cursor, once the requester applied the message and stored its cursor (spec/sync-streams.md §4 Reports); a Pull's `cursor` is where to read on from and reports nothing applied. Events (below) carry an add only for an entry whose bytes the server holds, its bytes inline only if its size is at most `inline_limit` and not for an entry the requester's own stream showed present (spec/sync-judgement.md §3 `known`); a requester fetches any added blob whose bytes it lacks. A Stream with no `cursor` carries a relay-only entry (spec/sync-compaction.md §2), which no position names, or Full and Refused events; its `report` is false. A Stream with a `cursor` and no events moves the stream there and asks `report` (an ended member reaching its `until`, spec/sync-streams.md §4). A side answers a connection's Pulls and top-bit Fetches in the order they arrive (PullReply, FetchReply or Error); a requester counts one of them still unanswered when a later one's answer arrives as skipped: a skipped Pull as refused, a skipped Fetch as answered with none of its IDs.
- **Fetch** between such nodes (spec/sync-streams.md §4, Stream), with a top-bit id: blob IDs grouped by sync ID, each a member of the connection's shared set, a blob ID at most once in a Fetch (the reply's items name blob IDs alone); an ID it does not hold, or of a sync ID it does not share there, is answered with none; `max_reply` and a prefix as below (Fetch), its items in request order.
- **Digest** (spec/sync-opens.md §3): `digest` 32 bytes. **Members**: at most 4096 sync IDs, `more` true on every page but the last; sent only after a Digest that differs. Neither is answered.
- **Resume** (spec/sync-opens.md §3): dialer to listener, after the dialer's `Proved`, at most one per connection (a second, or one before a Prove, is answered Error 2; a listener the dialer proved no key actor to, keeping no record for this connection, answers Error 1, and the dialer sends NoRecord). `nonce` 32 random bytes; each `tag` 32 bytes, at most `MAX_RESUME_TAGS` of them, as many as fit one message. **Resumed**: the listener's own `nonce`, and `tag` when it holds a listed record.
- **Twin** (spec/sync-opens.md §1 Twin): either side, on a connection holding a record, about another; `tag` 32 bytes. **Twinned**: `tag` when the receiver matched it. A Twin on a connection holding no record is answered Twinned with none.
- **Register**: replies Ok (also when the step already is the head), or an Error without the head (spec/sync-ids.md §6):
  - 2 when the step's sync ID is not the message's, or the claim set does not hash to `claims_hash`;
  - 1 for a genesis step that does not verify;
  - 13 for a child step of an unknown sync ID;
  - 9 for a step that is not a valid child of the head, and a genesis step while the node holds a step of the sync ID;
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
- **Events**: 0 an entry added or a deposited one stamped, its wrap and stamp replaced (no stamp: deposited), 1 deleted, 2 the sender is full for the sync ID (`full` a bool: true full, false room again; only in a Stream with no cursor, spec/sync-streams.md §4), 3 a new head (without claim set), 4 the sender refused a pulled entry for anything but room, with the refusal's code (neither 0 nor 12; only in a Stream with no cursor, spec/sync-streams.md §4). Expiry produces no event.
- **Fetch** (spec/sync-streams.md §4): items in request order, possibly a prefix of the request when the reply would exceed `max_reply` (in `SMALL_REPLY..=REPLY_BUDGET`), possibly none below `REPLY_BUDGET`; the requester asks the rest again under `REPLY_BUDGET`.
- **Stranded** and **Suspect** (spec/permissions.md §4): node to node only, answered Ok whatever the receiver does with them. Stranded names a sync ID the sender is stranded on and the holder (a tid) it reads the sync ID's thing through, with that holder's holder keys (§9 Holder keys); Suspect carries suspect entries of things in the sync ID's sync unit, `thing` a tid, `ak` an AK, `digest` 16 bytes, as many as fit `MAX_MESSAGE` per message.
- **Client port** (kinds 24-29): served on every connection of a node, at every listener and on those it dialed (spec/sync-transport.md §5, One key). `session_id` is 16 bytes; `secret` is exactly 32 bytes.
  - **Auth**: answered Reply `[0, []]`.
    - A main session (the unix transport, spec/sync-transport.md §6) sends Auth without `secret`.
    - A client-actor session, on a keyed transport, sends it with its bearer secret (spec/data-model.md §9), which binds the session to the client actor of the `clients^.0` entry whose `secret_hash` is its BLAKE3, compared in constant time, `until` not passed.
    - Any other Auth is answered Error 1: no matching entry, no secret on a keyed transport, a secret on the unix transport, a second Auth of a client-actor session.
    - Past `MAX_CONNS_PER_CLIENT` authenticated sessions of one client or `max_clients` of all clients: Error 4. An ended session (below) counts toward neither.
    - A Call or Sub before an Auth answered by Reply is answered Error 1.
  - **End of a client-actor session**: it ends when its entry goes, its `secret_hash` changes or its `until` passes. Each request is checked at the time it runs and does not run if any of those holds.
  - **A client actor's rights**: every method of a client-actor session runs as its client actor, by that actor's rights at that time.
    - A thing the actor may not read (spec/sync-judgement.md §1, and not a kept copy it reads, spec/permissions.md §3) answers every method as a thing the node does not know.
    - A write the actor may not make is code 3, a `link` value anywhere in its write code 8.
    - A revert needs the actor's rights on every write it makes and on everything the reverted commit touched, and lists nothing the actor may not read (code 3).
    - Methods carrying state beyond a thing the actor may read are for main sessions only, code 11 otherwise.
    - This is the client's node's own rule, not a validity rule: receivers judge its commits by the signing account's rights (spec/permissions.md §1), and the actor its path names only by whether the account acts for it (spec/permissions.md §5.2 Interim), never by the actor's rights on what it writes.
  - **Write nonces**: a write's nonce is below 2^62, from 1 per (identity, session id).
    - A client resending a write it had no answer to sets bit 62.
    - A node that holds no write outcomes for that session answers such a write code 12 and does not run it, as it does every later marked write it does not remember until the session's next unmarked one.
    - One that holds them answers a nonce it remembers with its first result.
    - A session's write outcomes do not outlive the node process.
  - **`max_reply`** is in `SMALL_REPLY..=REPLY_BUDGET`.
    - A Reply whose message exceeds it is replaced by `[1, 5, max_reply]`.
    - A delivery whose Notify would exceed its Sub's `max_reply` is sent as `[2, source]`, and a Notify still exceeding it as `[1]`.
  - **Methods**: one line per row, `[arg*] -> value`; a method not listed is `[1, 11, text]`. Every row answers as its session's actor (above). The forms of a read result, path, write op, origin and commit: notes/client-port.md §2 until stable. `Opt(x)` is `[]` or `[x]`; a stamp is `[commit id, actor, ts, received]`.

    | method | row | args -> value |
    |---|---|---|
    | 0 | whoami | `[] -> [me, node, root]`, `root` the account root (spec/sync-set.md §1) |
    | 1 | get | `[tid, ak, path] -> read result` |
    | 2 | aspects | `[tid] -> [ak*]` |
    | 3 | has content | `[tid] -> bool` |
    | 4 | holds | `[tid] -> bool` (its creation is held) |
    | 5 | backlinks | `[tid] -> [[thing, ak, kind]*]`, kind 0 strong, 1 weak, 2 ticket: the known references to it (spec/data-model.md §8), only from things the actor may read |
    | 6 | grants | `[tid] -> [[holder, role, Opt(until), retain_copy, Opt(may_grant), from_now]*]` |
    | 7 | role on | `[tid] -> Opt(role)`, the actor's |
    | 8 | created | `[tid] -> Opt(stamp)` |
    | 9 | changed | `[tid] -> Opt(stamp)` |
    | 10 | write | `[nonce, actor, [ak*], [op*], Opt(expiry)] -> Opt(commit)` |
    | 11 | undo | `[nonce, scope] -> Opt(commit)`, scope `[0, tid]` or `[1, [[tid, ak]*]]` |
    | 12 | redo | `[nonce, scope] -> Opt(commit)` |
    | 13 | revert | `[nonce, commit id] -> commit` |
    | 14 | undo target | `[scope] -> Opt(commit)` |
    | 15 | redo target | `[scope] -> Opt(commit)` |
    | 16 | listing | `[address, query] -> [[commit*], more, complete]`, address `[0, scope]` a scope's writes, `[1, tid, ak]` a signal's fires, `[2, tid, ak, commit id]` a fire's versions; query `[from, Opt(limit), [actor*], [kind*], Opt(reverts), Opt(reverted_by), Opt(in_effect)]`, from `[0]` newest, `[1]` oldest, `[2, position]` before, `[3, position]` after; kind 0 content, 1 revert, 2 role, 3 snapshot; at most what fits `max_reply`, `more` set when cut |
    | 17 | listed commit | `[address, commit id] -> Opt(commit)` |
    | 18 | contact card | `[] -> text`; main only |
    | 19 | settle | `[] -> []`, after every Notify for changes before it |
    | 20 | now | `[] -> wall ms` |
    | 21 | status | `[] -> [connected, [[tid, state, not_taking, leaving]*], [kept tid*]]`, state 0 synced, 1 syncing, 2 not connected, 3 stranded; kept: things held and synced no more (retained copies, spec/permissions.md §3 Retain); for a client actor only the things it may read, `connected` the connections with one of them open |
    | 22 | holders | `[tid] -> [[actor, kind, role, Opt(until), [through*]]*]`, kind 0 actor, 1 link, 2 key; nothing behind a holder the actor may not read |
    | 23 | profile | `[] -> tid`; main only |
    | 24 | profile of | `[account] -> Opt(tid)`; main only |
    | 27 | wait synced | `[scope] -> []`, scope `[0]` all, `[1, tid]` a thing; waits; main only |
    | 28 | import contact | `[card text] -> account`; waits; main only |
    | 29 | redeem | `[link text] -> tid`; waits; main only |

    A row that waits is a Sub with filter 5, never a Call (a Call naming one is code 11).

    | filter | Reply | Notify `[0, value]` |
    |---|---|---|
    | `[0, tid, ak, path]` | read result | `[read result, origin]`; `[2, max_reply]` above it |
    | `[1, tid]` | `[[ak, read result]*]`, the aspects present | `[ak, read result, origin]`; `[2, [ak, max_reply]]` above it |
    | `[2, tid]` | as row 6 | as row 6 |
    | `[3]` | as row 21 | as row 21 |
    | `[4]` | `[]` | `[kind, [tid*], Opt(commit id), Opt(peer), detail]`, one per diagnostic of the node, kind 0 bad input, 1 colliding record, 2 parked, 3 pending, 4 overlapping counters, 5 removed, 6 callback, 7 not carried (spec/sync-set.md §2 Not carried), 8 stranded, 9 uncommitted, 10 ephemeral refused, 11 mismatch, 12 storage, 13 repair, 14 own write invalid, 15 unreadable, 16 disputes unexamined, 17 own write failed, 18 sync stopped, 19 clock skew, 20 input capped, 21 connection (an unknown kind reads as 0); main only |
    | `[5, method, [arg*]]` | `[]` | `[0, value]` or `[1, code, detail*]`: the row's outcome, once, whatever the room; an Unsub or the connection's end cancels it; main only |
    | `[6, address]` | `[]` | `[0, commit id, Opt(commit)]` a commit reading otherwise at the address (as row 17 reads it then), `[1]` read the address again, `[2, code, detail*]` ended |

    A Notify of filters 0-3 goes only when its value reads otherwise than the last one sent (an error read always goes); every Notify is read as the actor when it is sent. A Sub of a filter marked main only, from a client-actor session, is answered `[1, 11, text]`.
  - **Outcome error codes**: an unknown method is `[1, 11, text]`.

    | code | meaning | detail |
    |---|---|---|
    | 1 | unknown thing | `[tid]` |
    | 2 | unknown actor | `[tid]` |
    | 3 | permission | `[tid, role]` |
    | 4 | type | `[path, text]` |
    | 5 | too large | `[limit]` |
    | 6 | not undoable | `[commit, reason]` |
    | 7 | stranded | `[[tid*]]` |
    | 8 | invalid | `[text]` |
    | 9 | storage | `[text]` |
    | 10 | network | `[text]` |
    | 11 | unsupported | `[text]` |
    | 12 | outcome unknown: the write may have applied | `[]` |
    | 13 | refused: this session may not use the node | `[text]` |
    | 14 | closed: the node closed while the call was in hand | `[]` |
    | 15 | in use: the node's store is open elsewhere | `[]` |
    | 16 | not enabled: a fire of an external signal the thing's current setting does not enable, by an actor holding no write on it (spec/permissions.md §5.2 External fires) | `[tid, ak]` |
    | 17 | leaves no admin: the write would leave the thing with no standing admin and carries no adminless mark (spec/permissions.md §1, The last admin) | `[tid]` |

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
  | 3 | too large (a blob above `MAX_BLOB`, a relay-only blob above `MAX_RELAY_BLOB`; an oversized message is answered as malformed, 2) |
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
  - Fetch: 1024 IDs in all its groups.

## 12. Decoder limits
- Any object: CBOR nesting at most 512 deep, values inside it at most `MAX_VALUE_DEPTH` (spec/data-model.md §5); no array or map longer than the bytes that remain.
- **Memory**: what a node holds of an input is bounded by the bytes its signer delivered for it, never by what they name: a header holds its lists only as linked to it (§4), a peer's filter is held as coded (about the bytes of its Beacons). A read whole (node policy bound `b`) holds at most about `b` of what it reads: a large value at most `b` bytes decoded beside its `b` canonical bytes, whatever its shape; an aspect's state at most `b` bytes as held in memory, loaded piece by piece and refused before the piece that passes it. Past it the read fails as too large (local), not as bad input.
- Blob `MAX_BLOB`; frame `MAX_MESSAGE`; a message at most 2^20 CBOR data items in all, those of the canonical bytes its byte strings carry (steps, claim sets, entry boxes) included; AK `MAX_AK_BYTES`; URL 256 bytes.
- Header: each inline list at most `CHUNK_THRESHOLD` bytes, each linked one at most `MAX_LIST_BYTES`; a `Path` at most `MAX_PATH_THINGS` listed things; a hashed `path` one 34-byte hash per thing written, always inline, within `MAX_BLOB` with the rest of the commit (about 220 KB at the 6 500 things a blob holds). Prefix: 65535 groups of at most 3 commitments, within the blob. Claim set: `MAX_CLAIMS` keys; a claim set with its entry boxes is at most `MAX_MESSAGE` − 64 KiB. Tree node and link page: 512 links (a tree node one length per link); tree level 48; link page levels unbounded, a decode holding one link page per level on its way down (§6). Sequence run: `MAX_RUN` elements, a list run's `Content` closing at `CHUNK_MAX` bytes; runs without `Content` in a writer or import delta: `MAX_DELTA_BARE` elements in all (spec/crdt.md §3.3). Link: §10. Messages: §11.2.
