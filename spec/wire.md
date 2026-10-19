# Wire formats
> Summary: Byte layouts of everything that leaves a node: common encodings, format constants, creation records, commit headers and commit blobs, blob framing and padding, the chunker and chunk trees, boxes, registration steps and claim sets, inbox blobs and signal envelopes, links and recovery cards, the node-to-node protocol, bundles, decoder limits.

## 1. Conventions
- Every structure below is canonical CBOR in the profile of spec/data-model.md §5 unless it is given as a fixed byte layout. `[a, b]` is an array with exactly those positions; `Opt(X) := [] | [X]`; `X*` repeats X zero or more times, `X+` one or more. A decoder rejects any other length, a wrong major type, or an item outside its stated size.
- Inside structures (not values): a tid is a 15-byte byte string, a commit ID, blob ID, step ID or hash a 32-byte byte string, a label ID a 16-byte byte string, a time (wall ms) or `ts` an unsigned integer. A **value** (spec/data-model.md §4) embedded in a structure keeps its value encoding (tags included).
- A role in a structure is a uint: 0 read, 1 write, 2 admin. A purgeable-by class: 0 `nobody`, 1 `admin`, 2 `author`, 3 `writer`. A token level: 1, 2, 3 (spec/crypto.md §7).
- An epoch in a structure is `[n, nonce]` (uint, 16-byte byte string).
- **AD tuples**: an AEAD associated-data tuple `(a, b, ...)` written in spec/crypto.md is the canonical CBOR array of its items in the encodings of this section; layouts below give each one.
- Signed digests: a signature's digest (spec/crypto.md §2) is BLAKE3 of the canonical bytes of the array the layout names.
- Ed25519 keys and signatures in structures are raw (32 and 64 bytes) where a layout says `pk` or `sig`; where it says `signing_key` or `signature` it holds the agility enum value (§3).

## 2. Constants
Format constants (fixed by format version 1, spec/versioning.md §1):

| constant | value |
|---|---|
| format version | 1 |
| `MAX_BLOB` | 8 MiB (8 388 608 bytes), whole blob (prefix and ciphertext) |
| `CHUNK_THRESHOLD` | 128 KiB (131 072 bytes) |
| `PAGE_TARGET` | 64 KiB (65 536 bytes) |
| chunker | `CHUNK_MIN` 16 KiB, `CHUNK_MAX` 256 KiB, gear table and boundary rule §6 |
| tree fan-out | at most 512 links per interior node or link page (§6) |
| `MAX_COMMITMENTS` | 16 token commitments per blob prefix |
| `MAX_CLAIMS` | 65 536 keys per claim set |
| `MAX_DRIFT` | 1 hour |
| `MEMBERSHIP_KEEP` | 90 days |
| `INBOX_LIFETIME` | 90 days |
| `HEARTBEAT_MIN_LIFETIME`, `HEARTBEAT_MAX_LIFETIME`, `HEARTBEAT_MIN_INTERVAL` | 1 day, 14 days, 6 hours |
| `RESOLUTION_HOPS` | 8 (spec/permissions.md §7) |
| core schema ID | 16 zero bytes, revision 1 (spec/data-model.md §9) |

Blind-node policy (recommended): `TOMBSTONE_LIFETIME` 30 days; deposit budget spec/sync.md §5. Node-to-node protocol limits (version 1, not format constants): §11.

## 3. Creation records and agility enums
- Agility enums (spec/crypto.md §8) are values: `signing_key = enum { 1 ed25519(blob) }` (32 bytes), `signature = enum { 1 ed25519(blob) }` (64 bytes), `kem_key = enum { 1 x25519_mlkem768(blob) }` (`pk_x || pk_m`, 1216 bytes), `sealed = enum { 1 x25519_mlkem768(blob) }` (`ct_x || ct_m || AEAD`). Each encodes as `1617([1, h'...'])`.
- A **creation record** is the value `creation = struct { 0 owner: tid, 1 key: signing_key, 2 nonce: blob }` holding exactly one of fields 0 and 1, and a 32-byte nonce: an ordinary thing `{0: owner, 2: nonce}`, a key actor `{1: key, 2: nonce}`. Its canonical encoding is what the tid hashes: tid = first 15 bytes of BLAKE3(canonical bytes). `/created` holds this value (spec/data-model.md §9); a `/created` whose read does not hash to its tid, or holds both or neither of fields 0 and 1, is bad input; an unknown `signing_key` case parks the thing (spec/versioning.md §2).
- A link key's or recovery key's nonce is `kdf("creation nonce", seed, "")`; a node's is random.

## 4. Commits
```
Header    := [version, author, actor, kind, ts, form, schemas, aspects, chunks, purge,
              undoes, salt, tokens, frontier, origins]
Aspect    := [tid, ak, lo, hi, Retention, expires, schema, tokens, hashes]
Retention := [by, at_least, at_most]
Bound     := {? 0: abs, ? 1: rel}
Token     := [level, token_hash]
Chunk     := [blob_id, [[ti, token_hash]*]]
PurgeItem := [commit_id, tid, ak] | [tid, ak]
Origin    := [commit_id, author, actor, ts]
CommitBlobPlaintext := [Header, signature, [Part*]]
Part      := [ai, di, delta]
```
Header fields by position:
0. `version`: uint, the format version (1).
1. `author`: tid of the signing key actor. 2. `actor`: tid of the actor it acts for.
3. `kind`: 0 content, 1 membership, 2 content compaction snapshot, 3 membership compaction snapshot, 4 import, 5 roster snapshot (spec/commits.md §2).
4. `ts` (spec/crdt.md §2.2). 5. `form`: 0 node form, 1 commit form (spec/commits.md §3).
6. `schemas`: `[[schema_id (16 bytes), revision]*]`, sorted by schema ID, distinct, at most 256.
7. `aspects`: `[Aspect+]` sorted by the canonical bytes of `[tid, ak]`, distinct.
8. `chunks`: `[Chunk*]` sorted by blob ID, distinct: every chunk, tree-node and page blob the deltas introduce, with its chunk token hashes; `ti` is an index into `tokens`, ascending, one per token secret of the delta that created the blob.
9. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[commit_id, tid, ak]` names that commit's deltas on that aspect; `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`.
10. `undoes`: `Opt(commit_id)`.
11. `salt`: 16 random bytes (spec/crypto.md §7).
12. `tokens`: `[Token*]` sorted by canonical bytes, distinct: one per token secret of the commit's deltas, `token_hash` 16 bytes; a token no aspect lists is bad input.
13. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9); present iff the commit is a membership commit carrying an explicit demotion (spec/permissions.md §5).
14. `origins`: `[Origin*]` sorted by commit ID, distinct; non-empty iff `kind` is 4 (spec/permissions.md §7).

Aspect fields: `tid`; `ak` (text, spec/data-model.md §2, at most 1024 bytes); `lo`, `hi`: the counter range (`lo = hi = 0` for kinds 2, 3, 4; else `1 <= lo < hi`); `Retention`: `by` (purgeable-by class), `at_least` and `at_most` bounds, each a map with optional `0: abs` (wall ms; `2^63 - 1` means forever) and `1: rel` (ms after the body is replaced), `{}` for no bound; `expires`: `Opt(T)`; `schema`: `Opt(index into schemas)`; `tokens`: `[ti*]`, ascending indices into the header's `tokens`, the token secrets this aspect's deltas call for; `hashes`: `[delta_hash+]` (32 bytes each), exactly one for kinds 0, 2, 3, 4, sorted and distinct for kinds 1 and 5.

- **Inline or link**: `aspects`, `chunks`, `purge`, `tokens`, `origins` and the frontier are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the dedup secret of the header's `actor`. A decoder rejects an inline list above the threshold or a link below it. Header-list chunks carry the token commitments of §5.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the author's key under `"osis v1 commit" || commit ID`.
- **Commit blob** plaintext: `CommitBlobPlaintext`. A `Part` holds one delta: `ai` indexes `aspects`, `di` that aspect's `hashes`, `delta` is the embedded `Delta` or `Snapshot` array (spec/crdt.md §3.2, §8) whose canonical bytes hash to that delta hash. Parts sorted by `(ai, di)`, distinct; zero parts is allowed (every delta purged). The blob's prefix commitments are those of the tokens its parts' aspects list (§5); its expiry is their common `expires`.
- A header violating a rule of spec/commits.md §2 (an aspect of the wrong class for its kind, `expires` or a purge item on a membership commit, `expires` on a commit with a purge request (spec/commits.md §5), a frontier outside a demotion, more than one hash for a kind with one delta per aspect) is bad input.

## 5. Blob framing
A blob is `prefix || ciphertext`, at most `MAX_BLOB` bytes. The prefix is a fixed byte layout:

| offset | size | field |
|---|---|---|
| 0 | 1 | framing version: 1 |
| 1 | 16 | salt, random per encryption |
| 17 | 8 | expiry `T`: le64 wall ms; 0 means none |
| 25 | 1 | n: number of commitments, 0..`MAX_COMMITMENTS` |
| 26 | 17·n | commitments: level byte (1..3) `||` 16 bytes (spec/crypto.md §7), strictly ascending as 17-byte strings |

- The ciphertext runs from offset `26 + 17n` to the end: XChaCha20-Poly1305 under the blob key, nonce 24 zero bytes, AD = the prefix bytes, plaintext = the padded plaintext. **Blob ID** = BLAKE3(whole blob).
- **Padding** (Padmé): for a plaintext P, let `L = len(P) + 1`, `E = floor(log2 L)`; if `E = 0`, `padme(L) = L`; else with `S` the bit length of `E` and `m = 2^(E - S) - 1`, `padme(L) = (L + m) & ~m`. The padded plaintext is `P || 0x80 || 0x00^(padme(L) - L)`. To unpad: strip trailing `0x00` bytes, then one `0x80`, which MUST be present; the padded length MUST equal `padme(len(P) + 1)`. Anything else is bad input.
- Plaintext per blob kind: commit blob `CommitBlobPlaintext` (§4); chunk: the raw chunk bytes; tree node and link page: §6; page: §6; inbox blob: §9 (its ciphertext is a sealed box, not the AEAD above); signal envelope: §9.
- Commitments: a commit blob, chunk, tree node or page carries one commitment per token of the deltas it serves (spec/crypto.md §7): at most one per level. A header-list chunk (§4) carries the commitments of every token of the commit when the commit has at most 16, else of its level-2 tokens only (provisional, issues/header-list-commitments.md). A header-list chunk's expiry is the greatest `expires` of the commit's aspects when every aspect has one, else none.
- **Wrap**: XChaCha20-Poly1305 under `kdf("wrap", label read secret)`, nonce = first 24 bytes of the blob ID, empty AD, plaintext `suite (1) || blob key (32)`: 49 bytes. A filler is 49 random bytes.
- A node that does not know a blob's framing version stores and relays it as a blob with no expiry and no commitments.

## 6. Chunker, chunk trees, pages
- **Gear table**: `G[i]` (i = 0..255) is the little-endian u64 at bytes `8i..8i+8` of the 2048-byte BLAKE3 XOF output of the ASCII string `"osis v1 gear table"` (unkeyed).
- **Chunker** over a byte sequence: at each chunk start `h = 0`; for each byte b, `h = (h << 1) + G[b]` (mod 2^64), and the chunk ends after that byte if its length is at least `CHUNK_MIN` and `h >> 48 = 0`, or its length is `CHUNK_MAX`. The last chunk ends at the end of the sequence.
- **Chunk tree** of a large atomic value (spec/data-model.md §6) or a linked header list or frontier (§4): the leaves are the chunks of its canonical bytes. Level 1 groups the leaf links in order into nodes; a node closes after a link when it holds at least 2 links and the link's content hash begins with byte `0x00`, or when it holds 512 links; the last node closes at the end. If a level yields one node, that node is the root; else the links to its nodes are grouped the same way into level + 1. The root is always an interior node, even over one chunk.
- A tree node's plaintext is `[level, [LINK+]]`: level 1 nodes link chunks, level k nodes link level k−1 nodes. Levels are at most 48.
- **Link content hash** (spec/crypto.md §6), keyed by the dedup secret: of a chunk, `kdf("link", d, chunk bytes)`; of a page or link page, `kdf("link", d, plaintext)`; of a tree node, `kdf("link tree", d, le64(level) || the content hashes of its links in order)`. The root's content hash identifies the value. A reader verifies the content hash of every link it resolves; a mismatch is bad input.
- **Pages** (spec/crdt.md §8): the gear hash runs over the concatenated canonical encodings of the array's elements, `h = 0` at each page start and never reset inside a page; a page closes after the first element at one of whose bytes the page length is at least `CHUNK_MIN` with `h >> 48 = 0`, or at whose end the page holds `CHUNK_MAX` bytes or more; the last page closes at the end of the array. A page's plaintext is the canonical array of its elements. If the resulting `[LINK+]` would exceed `PAGE_TARGET` bytes, its links are grouped into link pages by the tree-node rule (level 1 only), each a blob with plaintext `[LINK+]`, and the fragment holds the links to the link pages. A fragment needing a third level cannot be written.

## 7. Boxes
- A sealed box (spec/crypto.md §1) is `ct_x (32) || ct_m (1088) || AEAD_K(nonce 24 zero bytes, AD, payload)`, held in a `sealed` value (§3).
- **`/secrets` box** (spec/crypto.md §4), a `box` value (spec/data-model.md §9) keyed by `box_key`. AD = `[actor, member, role, n, nonce, form]` with the key's epoch `[n, nonce]` and `form` = `[0, Opt([kn, knonce]), suite]` for the sealed form (the recipient keyset epoch, none for a key actor) or `[1, [sn, snonce]]` for the symmetric form (the epoch of s).
  - Sealed payload: `[[role, n, nonce, secret]+]` ascending by role, secret 32 bytes: one item for an actor member, every role written for a key-actor member.
  - Symmetric `wrap`: XChaCha20-Poly1305 under `kdf("box", s)`, nonce = first 24 bytes of BLAKE3(AD), plaintext `suite (1) || secret (32)`: 49 bytes.
- **Entry box** (spec/sync.md §2): a `box` value, AD = `[label_id, step_key, form]`, payload as above with the read role only.
- **History box** (role r, epoch e): XChaCha20-Poly1305 under `kdf("history", secret_r[e])`, nonce 24 zero bytes, AD = `[actor, role, n, nonce]`, plaintext `[[n, nonce, secret]*]` ascending by `[n, nonce]`; the `/secrets` history map holds the ciphertext.
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
- A claim key pair is the Ed25519 key pair with seed `kdf("label claim", DH(step private key, M's X25519 key), label_id || step_key)`; a static entry is `BLAKE3("osis v1 static claim" || label_id || pk)` with `pk` the key actor's raw Ed25519 signing key.
- `/label` stores a step as the canonical bytes of `Step` and its claim set as those of `ClaimSet` (`step_record`, spec/data-model.md §9).

## 9. Inbox blobs and signal envelopes
- **Inbox blob** (spec/crypto.md §5): prefix with expiry = the sender's corrected wall ms + `INBOX_LIFETIME` and no commitments, then a sealed box (§7) to the recipient's newest read keyset KEM key with AD = `[recipient, "inbox", prefix bytes]` and payload the padded (§5) canonical bytes of
  `InboxPayload := [CommitBlobPlaintext, [[tid, label_id, [address*]]*]]`:
  the membership commit with the parts about the recipient (§4), then for each thing it names, its label ID and server addresses (`address` values, spec/data-model.md §9), sorted by tid.
- **Signal envelope** (spec/sync.md §9): a blob (§5) with no expiry and no commitments, wrapped under the label like any blob, at most 64 KiB. Plaintext: the padded canonical bytes of `[SignalBody, signature]` with
  `SignalBody := [node, actor, ts, tid, kind, target, schema, value]`: sender node tid, actor tid, `ts`, target thing tid, kind (text, as an AK), `Opt(target node tid)`, `Opt([schema_id, revision])`, the value. The `signature` value is the sender node's under `"osis v1 signal"`, digest BLAKE3(canonical `SignalBody`).
- Publish authorization: `[key, sig]`, key 0 for the label's write key or 1 for its deposit key, `sig` raw Ed25519 under `"osis v1 signal publish"`, digest BLAKE3(canonical `[label_id, blob_id, wrap]`).

## 10. Links and recovery cards
```
Link := [1, seed, target, k, k_label, [address*], [peer*]]
peer := [dialable, [relay*]]
Card := [1, seed, person, home_label, [address+]]
```
- `Link` (spec/permissions.md §9): format 1, L's 32-byte seed, the target tid, K's tid, K's label ID, server addresses of K's label, and the sharer node's P2P reach for first contact: `dialable` its 32-byte dialable key, `relay` relay URLs (`/reach`, spec/data-model.md §9). A redeemer with no common server dials a peer, which serves K's label as a member peer (spec/sync.md §5).
- `Card` (spec/permissions.md §9): format 1, the recovery key's 32-byte seed, the person actor's tid, its home label ID, server addresses.
- Caps: at most 8 addresses, 4 peers, 4 relays per peer; URLs at most 256 bytes.
- Text forms: `osis://link/` or `osis://card/` followed by the unpadded base64url of the canonical bytes.

## 11. Node-to-node protocol (version 1)
### 11.1 Framing and handshake
- Each direction of the stream (spec/sync.md §10) is a sequence of frames: a 4-byte big-endian length `len`, `1 <= len <= MAX_MESSAGE` (9 MiB, 9 437 184 bytes), then one canonical CBOR item of `len` bytes. A frame breaking a rule of this section is answered by Error 2 and may end the connection.
- Each side sends `Hello := ["osis", [version+], wall_ms, challenge]` as its first frame, without waiting for the other's: supported protocol versions ascending (at most 16), its corrected wall clock, 32 random bytes. The session uses the greatest version both list; with none in common, both close. This section defines version 1.
- Every later frame is a message `[kind, id, ...]`. `id < 2^32` is chosen by the requesting side and not reused while its request is outstanding; replies carry it; `id = 0` marks a message that has no reply (Push, Signal). Either side may send requests. A request of unknown kind gets Error 11. Replies may arrive in any order.
- **Static key** of a side: the 32-byte key the transport authenticated for it (a server: its address key; a peer: its dialable key). An open signature binds the opened side's static key and Hello challenge.
- Clock offset (spec/sync.md §6) is estimated from Ping/Pong round trips and Hello.

### 11.2 Messages
```
Error     [0, id, code]
Ok        [1, id]
Ping      [2, id, wall_ms]                     -> Pong [3, id, wall_ms]
Open      [4, id, label_id, proof]             -> Opened | Step | Error
Opened    [5, id, head, Opt(entry_box)]
Step      [6, id, step]
Register  [7, id, label_id, step, Opt(claim_set)]   -> Ok | Step | Error
Path      [8, id, label_id, Opt(after)]        -> PathReply [9, id, [step*], more]
Upload    [10, id, label_id, [entry+]]         -> Status
Status    [11, id, [code+], Opt(head)]
Deposit   [12, id, label_id, blob, wrap, sig]  -> Budget [13, id, code, entries_left, bytes_left, Opt(head)]
Delete    [14, id, label_id, [item+]]          -> Status
Sync      [15, id, label_id, Opt(cursor), inline_limit, [entry*], [gained*]]
                                               -> SyncReply [16, id, [event*], [want*], [code*], cursor, more] | Error
Reconcile [17, id, label_id, [range+]]         -> ReconcileReply [18, id, [range*]]
Fetch     [19, id, label_id, [blob_id+]]       -> FetchReply [20, id, [[blob_id, Opt([blob, wrap, Opt(stamp)])]*]]
Subscribe [21, id, [label_id+]]                -> Status
Unsubscribe [22, id, [label_id+]]              -> Ok
Push      [23, 0, label_id, [event+], cursor]
Signal    [24, 0, label_id, blob, wrap, auth]

proof  := [0, sync_pk, sig] | [1, step_id, claim_pk, sig] | [2, signing_pk, sig]
entry  := [blob, wrap, stamp]
item   := [blob_id, Opt(at), Opt(token), sig]
cursor := [log_id, seq]
event  := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, blob_id, at] | [3, step]
range  := [lower, upper, mode]
mode   := [0, fingerprint] | [1, [blob_id*]] | [2, [blob_id*], [blob_id*]]
```
Steps and claim sets are the canonical bytes of §8 as byte strings; blobs are byte strings; `wrap` 49 bytes; `sig`, `stamp` raw 64-byte Ed25519 signatures; `*_pk` raw 32-byte keys; `at` wall ms; `token` 32 bytes; `log_id` 16 bytes.

- **Open** (spec/sync.md §5): `sig` under `"osis v1 label open"`, digest BLAKE3(canonical `[label_id, challenge, static_key]`) with the opened side's challenge and static key; proof 0 by a sync key, 1 by claim key `claim_pk` at step `step_id`, 2 by a key actor's signing key (its static entry). Opened carries the head (without claim set) and, for proof 2, the head's entry box for that static entry. A match at a superseded step is answered by Step with that step's child (without claim set).
- **Register**: replies Ok, or Step with the head when the step is not accepted (spec/sync.md §5).
- **Path** (opened labels): the registration path after step `after` (from the genesis step when absent) toward the head, without claim sets, at most 1024 steps per reply; `more` is true when steps remain.
- **Upload** and the entries of Sync: `stamp` under `"osis v1 upload"`, digest BLAKE3(canonical `[label_id, blob_id, wrap]`). Status gives one code per entry in order; when any code is 9 it carries the head.
- **Deposit**: `sig` by the deposit key under `"osis v1 deposit"`, digest as for a stamp. Budget reports what remains of the label's deposit budget after the request.
- **Delete**: per item, `sig` under `"osis v1 delete"`, digest BLAKE3(canonical `[label_id, blob_id, Opt(at), Opt(token)]`): by the head's delete key without a token; with a token, by the head's write key for a level-3 commitment and its sync key for level 1 or 2 (spec/sync.md §5). `at` requests a timed delete.
- **Sync** (cursor sync and download, spec/sync.md §6): `cursor` is the peer's log position for the label (`log_id` names the log instance; a peer whose log no longer reaches `seq` or has another `log_id` answers Error 10); without a cursor the reply replays the label's live entries as add events. `entry` lists the requester's new stamped entries (status per entry in `[code*]`), `gained` the blob IDs gained from other sources since the cursor (at most 4096), `want` those the peer lacks. A blob's bytes travel inline in an add event iff its size is at most `inline_limit` and it has not crossed this connection yet. `more` true: repeat with the returned cursor.
- **Events**: 0 an entry added or its wrap and stamp replaced (no stamp: deposited), 1 deleted, 2 a timed deletion pending at `at`, 3 a new head (without claim set). Expiry produces no event.
- **Fetch** (spec/sync.md §5): items in request order, possibly a prefix of the request when the reply would exceed `MAX_MESSAGE`.
- **Subscribe** (opened labels): the peer then sends Push with each new run of log events, with blobs as in Sync under the connection's last `inline_limit` for that label. **Signal**: `auth` as in §9; the receiver forwards it unchanged to its other subscribers of the label and stores nothing.
- Status codes: 0 ok, 1 refused, 2 malformed, 3 too large, 4 rate limited, 5 deposit budget full, 6 tombstoned, 7 expired, 8 label not opened, 9 key not of the head, 10 cursor invalid, 11 unsupported, 12 storage cap reached, 13 unknown label.
- Per-message caps: Upload and Delete 1024 items; Fetch 1024 IDs; `gained` and `want` 4096; Subscribe and Unsubscribe 1024 labels; Reconcile 256 ranges, ReconcileReply 4096; a peer may refuse to hold more than 4096 open labels per connection (code 4).

### 11.3 Range reconciliation
- The set reconciled is the blob IDs of the label's live entries at each side. Bounds are byte strings of at most 32 bytes compared as if right-padded with zero bytes; a range holds the IDs with `lower <= id < upper`, `upper = []` meaning the end of the ID space. Ranges in a message are sorted and disjoint.
- **Fingerprint** of a set S: the first 16 bytes of BLAKE3(`le256(sum of S mod 2^256) || le64(|S|)`), each ID read as a little-endian 256-bit integer.
- The requester opens with one range over the whole space: mode 1 with its IDs if it holds at most 32, else mode 0. A side receiving a range:
  - mode 0: equal to its own fingerprint over the range: nothing; else, holding at most 32 IDs there: mode 1 with them; else it splits the range into 16 subranges of near-equal own counts (bounds of its choice) and sends each with mode 0, or mode 1 where it holds at most 32.
  - mode 1 at the responder: holding at most 1024 IDs there, mode 2 with the IDs it holds that the list lacks, then the listed IDs it lacks; else it splits as above. Mode 1 at the requester, and mode 2: nothing; the requester now knows both differences for the range.
- The requester sends the ranges it must answer in further Reconcile messages (at most 256 per message) until none remain, then fetches what it lacks and uploads or relays what the responder lacks (spec/sync.md §6).

## 12. Bundles
- A bundle file (spec/sync.md §11) is the 8 ASCII bytes `osisbndl` followed by frames as in §11.1, each one record. The first record is `[0, 1]` (bundle format 1). Records:
  - `[1, label_id, [[step, Opt(claim_set)]+]]`: the registration path from the genesis step to the head;
  - `[2, blob]`: blob bytes, before the first entry naming them, once per bundle;
  - `[3, label_id, blob_id, wrap, Opt(stamp)]`: an entry (no stamp: deposited);
  - `[4, label_id, blob_id]`: a deletion; `[5, label_id, blob_id, at]`: a pending timed deletion.
- An importer verifies paths and stamps as a server does and applies the records as a peer's log events received without a cursor; it skips records of unknown kind.

## 13. Decoder limits
- Any object: CBOR nesting at most 512 deep, values inside it at most 64 (spec/data-model.md §5); no array or map longer than the bytes that remain.
- Blob `MAX_BLOB`; frame `MAX_MESSAGE`; signal envelope 64 KiB; AK and signal kind 1024 bytes; URL 256 bytes.
- Header: 256 schemas; each inline list at most `CHUNK_THRESHOLD` bytes. Prefix: `MAX_COMMITMENTS`. Claim set: `MAX_CLAIMS` keys. Tree node and link page: 512 links; tree level 48. Sequence run: `2^16` elements (spec/crdt.md §3.3). Link and card: §10. Messages: §11.2.
