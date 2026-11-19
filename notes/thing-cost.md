# What one thing costs
> Summary: Measured cost of a dependent and an independent thing (rows by family, wire and stored bytes, commits, KEM and signature work, maker and readers); the survey of fixed overhead per commit, thing, aspect and reference with every byte placed and the ranked candidates to remove; why the big lines are what they are, what is open and rejected, states stored as their body, and the record riding in a newborn's own-secrets rotation.

Principle: **a thing costs its record, its content and what its readers need to open it, once each**. A second copy of the same bytes in the store, or a commit whose only job is ordering inside one transaction, is a defect; key material is paid per role a holder can be boxed at (notes/keys.md, A KEM key per role).

## Measured
Tests print the tables with `THING_COST=1`: engine `thing_cost::what_a_thing_costs`, `thing_cost::what_a_reader_costs`; osis `thing_cost::what_a_thing_costs_as_the_app_makes_it`. Stored bytes are logical engine rows (key plus value, `Engine::census` over `Transaction::census`); the osis test also gives both stores' physical bytes. These tests hand commits over in their opened form: "downloaded" there is that form, not the wire, and they count neither the sealed blob nor the sync store's entry rows, about half of what a node really sends and keeps for a small commit (Survey, below). KEM and signature counts are `osis_base::costs` counts in osis-crypto (`kem: keygen`, `kem: encapsulate`, `kem: decapsulate`, `sign`, `verify: *`).

Engine, the maker and its account's second node (`account_two_nodes`), each kind made once first:

| | dependent (mint admin the account root) | independent (mint admin the account) |
|---|---|---|
| commits | 1 (content: record, content, the root's `holds.0`) | 2 (rotation: `created.0` 88 B, `keys.0` 6288 B, `secrets.0` 1409 B, `sync.0` 451 B; content) |
| commit as stored, opened (`Engine::package`) | 703 B (header 357 B) | 9402 B (8820 + 582) |
| stored, maker | 1627 B | 14.9 KB |
| stored, second node | 1650 B (128 B of it the epochs its two content parts opened under, `ou/`, what passing them on needs) | about the same as the maker |
| maker work | 2 signs | 4 ML-KEM keygens, 5 signs |
| second node work | 1 commit verify | 2 commit verifies, no KEM |

Independent, stored rows at the maker: commit records `c/` (the two commits whole); aspect states 66-69 B each (`keys.0`, `secrets.0`, `sync.0`, `created.0`, content: each its one body, States stored as their body); `node/keysets` 948; `k/` (opened epochs) 1443; `node/metas` 603, `node/sealed` 592, `node/epoch intro` 408, `node/boxes to` 400, refs 354, `node/perm` 66; small local rows about 300. Dependent: `c/` 789, `node/metas` 255, refs 178, states 330, `t/` 74, `a/` 56, counters 104, states 136 (by body).

The KEM public keys (1216 B each, one per role, four roles) are 4864 B of the 9402 B a reader downloads and of the 14.9 KB stored at every holder (in the commit record; the `keys.0` state is that body until a second one joins).

Through the API, as the app makes them (osis, per thing over 10 makes; home is a dependent thing minted with the account root as admin): a dependent thing minted with home as admin (record, `retention^.0`, home's `holds.0`) 1.5 commits, 1.9 KB stored (2.0 KB physical), 1.2 KB downloaded; an independent thing held by home (minted with the account as admin, as `osis create --admin me` does) 3.5 commits (its rotation carrying its record, home's `holds.0` with its `retention^.0`, the account root's ticket for it, `tickets.0`, about 640 B, then compactions of home's `holds.0` and the root's `tickets.0`), 16.4 KB stored (18.6 KB physical), 10.9 KB downloaded, 8 signs, 14 sync-step verifications at the maker and 15 at the second node.

Another account granted read on an independent thing (engine `what_a_reader_costs`): one role commit of 3975 B (`secrets.0` 3093 B: sealed boxes at read and sync, each about 1.2 KB, and the history boxes again), 3 KEM encapsulations at the granter, 2 decapsulations at the reader; the reader stores about 31 KB for the thing (its content commit included) and the grant (its `keys.0` and `secrets.0` states hold two bodies, so they are whole); the granter's grow by the same, about 7.5 KB.

## Survey: fixed overhead per unit
Every figure is marked: **[M]** measured, **[C]** computed from spec/wire.md (each computed total matched the measured one to the byte), **[E]** estimated. Measured with throwaway prints, not kept as tests: in the engine fixture of `what_a_thing_costs`, each header item's `osis_base::cbor::encoded_len`, `Engine::seal_package` blob sizes, census diffs and every `osis_base::costs` count; and over real sync in a sync-harness world (`World::new(0)`, `add_node`, `pair(0)`: the maker and its account's second node), `net.between` bytes per direction, both nodes' engine census and sync store rows (`scan_local`), `disk_use`, frames by `OSIS_SYNC_TRACE=all`. The thing is a dependent thing minted with the account root, so the author is the account (built: `epoch` and inner signature present).

### One dependent thing with one small value, alone in a commit
**Wire [M]**: 1374 B maker to second node, 365 B back.
- Maker's Stream frame, 1285 B: the sealed blob 1006, blob ID 34, wrap 59, stamp 66, sync ID 17, cursor 82, heads and frame about 21. Then each side's Applied (cursor) about 89.
- Back: the second node streams the entry back without its blob (blob ID, wrap, stamp, cursor: about 276 B), then its Applied.

**Sealed blob, 1006 B [C]**, the commit as every stream carries it (`Envelope`, spec/wire.md §4, §5):

| bytes | what | paid per |
|---|---|---|
| 28 | prefix: version, salt 16, expiry 8, class, group count | commit |
| 34 | commitment group: count, level, blinded delete key 32 | delete-key group |
| 16 + 14 | blob AEAD tag; Padmé padding with its 0x80 (915 → 928) | commit |
| 1 + 357 | plaintext array head; header (below) | commit, plus per aspect |
| 71 | author signature: 64, agility enum wrapper 7 | commit |
| 98 + 1 | account's sealed inner signature 95 with heads; merge signatures `[]` | commit (decided removal) |
| 1 + 234 | sections list; t's section: heads 4, chain `[D]` 17, wrap 74, ciphertext head 2, AEAD tag 16, parts 121 (`[ai, delta]` each: `t:reg.0` 28, `created.0` 88) | thing touched |
| 151 | D's section: heads 3, empty chain 1, wrap 74, head 2, tag 16, part `holds.0` 55 | thing touched |

**Header, 357 B [M]**, 411 B with stated paths [C] (spec/wire.md §4 fields 1, 2, 17: signer 16, `path` 69 (the commit writes t and D: a 34 B salted hash each), `remains` 1, in place of author 16 and actor 16; each section's `Contents` then carries its thing's `Salted`, 22 B with the empty path; a commit writing one thing states `path` `[0]`, 2 B, and its section 2 B of `Contents` heads: 19 B of header against today's 32): version 1, author 16, actor 16 (the author's tid again), kind 1, ts 9, form 19 (session form: its 16 B nonce), expires 1, aspects 198, purge 1, undoes 1, blind 17, keys 37 (one level-2 delete key), frontier 1, ephemeral 1, epoch 35 (decided removal), rotation 1, reseal 1, array head 1. An aspect entry is 65 B: tid 16, ak 8 (`t:reg.0`), lo 1, hi 1, retention 1, keys 2, delta hash 34, replaces 1. The delta of a 3-character string is 28 B: nonce 17, empty sources and commits 2, fragment `[0, [], 0, "new"]` 8, head 1. So a 4 B value takes 95 B of the commit (entry 65, part 2, delta 28), 51 of them committing to it (hash, delta nonce).

**Per unit [C]**: per commit about 380 B (prefix 28, blob tag 16, padding, header without aspects 159, signatures 170; 247 after the decided removal) plus 34 per delete-key group and, on the wire, about 170 B of entry and frame plus the Applied and echo; per thing touched about 95 B of section (112 for a dependent thing: its chain); per aspect 67 B of header entry plus 2 + a delta of 21 B plus its value; a reference is its 16 B tid inside a value.

**Stored [M]**, the world's maker and second node:

| row | maker | second | what | per |
|---|---|---|---|---|
| sync store blob | 1006 | 1006 | the sealed blob: a second copy of the commit beside `c/` | blob |
| `c/` | 787 | 787 | key 34, record head about 50, the opened commit 703 | commit |
| `node/metas` | 253 | 253 | the header again: ts, kind, form, signer, the thing it acts on, epoch 32, each aspect's tid, ak, lo, hi (about 41 each), a flag byte per part | commit, aspect |
| `bp/` | 117 | 117 | key commit ID and blob ID 67; the prefix salt 16 again, the aspects its sections list, the parts held | commit |
| `E/` | 224 | 224 | key sync ID, blob ID 50; wrap 57, stamp 64, flags, class, expiry 8 and size 8 (both in the prefix), sources 2, stamp verdict 33 | entry |
| `X/`, `S/` | 100 | 50 | blob to its sync IDs 50; a peer showed holding it 50 (maker) | entry; entry per peer |
| `ou/` | – | 480 | 4 rows of 120: per part and one per header opening, keyed commit ID, ai, tid, epoch (n, nonce 32), the delta hash 32 again | part |
| aspect states | 134 | 134 | `created.0` 69, `t:reg.0` 65: each `[2, commit ID]` naming the body holding a 28-88 B delta | aspect |
| D's `holds.0` | 70-212 | same | the strong to t: state growth, or a 74 B table row per element once paged | reference |
| `node/refs` | 178 | 178 | from 49 and to 40 for each of two references (record's weak to D, D's strong to t) | reference |
| `t/` | 74 | 74 | the creation record again (in `c/`, named by the `created.0` state) | thing |
| `a/` | 54 | 54 | 27 per aspect with a state | aspect |
| `dw/` | 59 | – | the derived epoch t was sealed under while dependent | dependent thing |
| counters | 102 | – | 51 per (aspect, session); memory rows, the census counts them | aspect per session |

Totals: maker 1970 engine + 324 sync store + 1006 blob = 3.3 KB logical, 3.8 KB physical; second node 2289 + 274 + 1006 = 3.6 KB, 4.2 KB physical.

### Marginal units [M]
Wire is maker to second node (back in brackets); stored is logical, engine rows + sync store rows + sealed blob. Rows marked engine come from the engine fixture (no sync store); add about 300 B of entry rows and the blob.

| unit | wire | sealed blob | stored, maker | stored, second |
|---|---|---|---|---|
| one value, alone | 1374 (365) | 1006 | 3300 | 3569 |
| empty (record and holder's strong), alone | 1278 (365) | 910 | 2747 | 2937 |
| one value, per thing of 100 in one commit | 416 (4) | 410 | 1099 + 3 + 410 | 1196 + 3 + 410 |
| one value, per thing of 100 in 100 commits | 1504 (188) | 1075 | 3323 | 3461 |
| a second aspect, its own commit (engine) | – | 654 | 828 | 906 |
| per aspect, 8 aspects against 1 in one making commit (engine) | – | 105 | 292 | 240 |
| one more reference in a set, its own commit (engine) | – | 654 | 832-945 | 960-1038 |
| a 1-byte change to a value | 990 (365) | 622 | 779 + 324 + 622 = 1725 | 1003 + 274 + 622 = 1899 |
| a 1-byte change, steady (every third makes a compaction snapshot) | 1140 (449) | – | 871 + 278; blobs net 0 a cycle | about the same |

- The marginal reference inside a value: its 16-18 B in the delta, about 35 B of state, 89 B of `node/refs` rows per node; alone in a commit, the whole small commit.
- A replaced value: the old body's entry goes at the next compaction, leaving tombstone rows `T/` 91, `Y/` 50, `t/` 58, `w/` 79 (278 B per deleted entry at every node, for `TOMBSTONE_LIFETIME`); the maker keeps `node/snapshots` 144, `fn/` 115, `cv/` 101, `f/` 33 for the snapshot.
- A 1-byte change's blob, 622 B [C]: prefix 62, tag 16, padding 4, plaintext 540 (header 225: the 159 fixed and one 66 B entry; signatures 170; one section 143, wrap 74 and chain 17 in it).

### CPU and memory
- **Signatures [M]**: a small commit is 3 signs at the maker (commit, inner, stamp; the inner goes with the account redesign), 1 commit verify at the second node and 2 stamp verifications in the two-node world; no KEM. The inner signature is opened and verified only on demand (`flows::account`), never per receipt.
- **Rows read [M]**: engine 12 at the maker and 7 at the second node for a 1-byte change, 31 and 32 for a make. Whole world (both nodes, engine and sync store): 1365 rows read for a 1-byte change against 633 for an idle step, rising by about 30 per commit (1365, 1369, then 1464, 1468 after the compaction): the sync side reads some 40 times what the engine does per small commit. Not traced to its readers.
- **Sync-step verifications [M]**: none for a single small commit; 525 world-wide for 100 makes in 100 commits (7 in a step whose make compacted D's `holds.0`). Not traced.
- **Decodes [M]**: each part decoded once per node in the engine (`part decode` equals the parts).
- **Hashes [C]** (not counted by `costs`): at the maker, a delta hash per part, the commit ID, the account digest, the blob ID, the stamp's entry digest; at a receiver, the blob ID, the entry digest and the verdict hash per stamp check, the commit ID, a delta hash per part.
- **Memory per thing held [E]**, from the structs: a `Meta` per commit with its `View` (an `AspectView` of about 120 B per aspect), entries in `by_aspect`, `ranges`, `by_thing`, `by_actor`, `commit_blobs`, `blob_parts`; `Held::created` and `mint_admin_of` per thing; `derived_written` per dependent thing at its maker: of the order of 1-2 KB per small thing made alone, about half batched. Counter rows (51 B per aspect written) stay in memory until the session ends.

### What each cost is
(a) a job nothing else does, (b) a second copy or a pointer bigger than its data, (c) a job something present could do, (d) removed by a decided change.
- (a) Load-bearing, keep: `blind` (unlinks a commit's commitments across blobs, spec/crypto.md §7); the delete key and its prefix commitment (Delete and shredding by level); the delta hash per aspect (a part dropped or purged alone leaves a header that still verifies, spec/commits.md §5); the delta nonce of a sealed part (readers of the commit's other sections must not confirm a guessed small value from its hash); padding (size leakage); the stamp (a node keeping the sync ID unread checks a write came from a writer without learning who); the blob wrap (one ciphertext serves several sync IDs); the section chain (derivation without the record); the prefix salt; signatures.
- (b) The sealed blob and `c/` (two copies of each commit at every node, `bp/` relating them); `node/metas` (header fields again); `ou/`'s delta hash; `bp/`'s salt; `E/`'s expiry and class; `t/`; a state row naming a body smaller than itself; the entry echoed back; the blob ID beside an inline blob; `refs from` beside the state it indexes.
- (c) the tid in every aspect entry of one thing; the section wrap where a key could be derived; `dw/` (derivable from the mint admin's epochs); `X/` for a blob under one sync ID; the 33 B stamp verdict; the record's 32 B nonce behind a 15 B tid; the `created.0` delta nonce (the record carries its own).
- (d) `epoch` and the inner signature, 133 B per commit (issues/actors-one-mechanism.md); KEM keys of most independent things (issues/external-signals-taken-by-default.md). Stated paths cost 2 B (`[0]`) plus 16 B per listed thing for a commit writing one thing, and 34 B per thing in the header plus about 22 B per section (its `Salted`) for one writing several (notes/a1-spec/README.md, Bytes per commit); their evidence is not counted here.

### Ranked candidates
Savings per unit; [C] unless marked.
1. **Store each commit once.** Keep the sealed blob (served byte for byte: its ID and stamp cover it) and read bodies by opening it; `c/` keeps its head and what only it holds (leftovers, dropped parts), `bp/` its non-default cases. Saves about 700 B per small commit per node ([M] `c/` 511-787 against the blob). Changes the engine store layout; the engine already holds blobs (`G/`). Risks: a purge or shred must reach the one copy; commits under no sync ID and pending ones; an AEAD open per body read (state-as-body reads go through it); re-encryption (`Engine::relink`).
2. **`ou/` per (commit, thing, epoch), not per part.** An aspect bitmap; the delta hash only where it was not checked against the header. Saves about 350 B per one-value make and 130 B per small commit at every node but the maker ([M] 480 and 224 B). Risk: the passing-on invariant (`sync_ids::opened`): keep the epoch exact (its nonce), keep unchecked openings' hashes.
3. **No entry echoed to the peer it came from.** Saves about 276 B of wire per commit per peer pair, and the maker's `S/` row (50 B per entry per peer) if Held elsewhere is read from the Applied cursor. Risk: spec/sync-status.md §2 needs the peer to have stored the entry, and a changed wrap or stamp must still flow (event 0's replacement).
4. **Decided: drop `epoch` and the inner signature**: 133 B per commit on the wire, twice stored (blob and `c/`), 32 B in `node/metas`, one sign.
5. **Derive the section key** from the thing's read secret, the commit ID and a 16 B section nonce, instead of a 72 B wrap: saves about 57 B per thing per commit. Risk: one key per plaintext: re-sealing stripped parts must take a fresh nonce; copies keep the blob-key wrap.
6. **Embed a lone small delta in the header** where the commit has one section and its audience is the blob's: no hash, no delta nonce, no section. Saves about 50 B per aspect and about 112 B of section. Risk: per-part purge needs the hash, so only for a commit whose purge drops it whole; readers of another section never see it.
7. **`node/metas` from the record**: 150-250 B per commit per node. The in-memory `Meta` per held commit is the deeper question: an open reads every commit's.
8. **One tid per thing in the aspect list**: 16 B per further aspect of a thing in the header, 15 in `node/metas`. Wire format only.
9. **`refs from` read from the state**: 49 B per reference per node. Risk: dropping an aspect must read its state before clearing `refs to`.
10. **No `t/`**: 74 B per thing per node; the `created.0` state, keyed by tid, already reaches the record. Risk: hot record lookups go through the state reader.
11. **No `dw/`**: 59 B per dependent thing at its maker, derived from the mint admin's epochs since the thing's creation. Risk: a rotation's history must not carry epochs below a floor (spec/crypto.md §4 Current).
12. **Entry row**: the stamp verdict by head index, not 32 B (about 29 B); expiry and class read from the prefix (9 B); `X/` only for a blob under several sync IDs (50 B). Per entry per node.
13. **No blob ID beside an inline blob** on the wire (34 B per entry): the receiver hashes the blob anyway.
14. **Small items**: the record nonce at 16 B (16 B per thing in each copy); empty optional header fields (about 6 B); the signature's enum wrapper (7 B).

Not candidates: **one stamp over a batch** never pays: entries are stored and served one by one, so each keeps a proof, a Merkle path of 32 B per level, at least the 64 B saved from a batch of two up. **The session nonce** (18 B per commit against commit form) stays until session counters' job is studied: it is what lets one source span commits.

To study (CPU): the sync side's row reads per small commit (about 730 world-wide against the engine's 19) and the sync-step verifications in a burst of makes.

### Floors
- **Empty dependent thing [E]**, from the format with 4-6, 8, 10-12 and the decided removal. Batched, its record (about 36 B: admin 15, nonce 16) embedded as `created.0` with its aspect entry (about 20 B) and an element of its holder's `holds.0` (about 20 B): about 80 B on the wire, about 200 B stored per node (record and entry in the stored commit, state rows, `refs to`). Alone in a commit, add the commit floor below: about 550 B on the wire, 800 B stored per node. Today: 1278 B (365 back) and 2.7-2.9 KB.
- **Small commit [E]**: blob about 320 B (prefix 62, tag 16, header about 170 with the value embedded, signature 66, padding); on the wire about 470 B with its entry (wrap 57, stamp 64, sync ID and heads 30) and no echo; stored per node about 600 B (blob, entry row about 150, record head and meta about 100). Today: 990 B (365 back) and 1.7-1.9 KB. Below that, each further byte is the author's signature, the stamp, the delete key with its commitment, or the wrap: jobs nothing else does.

## Why the big lines are what they are
- **The keyset index names its body, not its KEM key** (`HeldKeyset::kem_in`, the earliest body carrying one; `apply::keys::keyset_kem` reads the key from that body or its dropped record when sealing, a rare path): a copy would cost 4.9 KB stored per independent thing at every node, and the same in memory (`Indexes::keysets` is in memory). The key sealed to is still one a valid noted body of the keyset carries. Earliest by body order, so two bodies of one epoch naming different keys (a writer re-publishing a keyset with junk) give every node the same key in any arrival order (`parts::` index checks compare a rebuild with the live index).
- **A state is stored as its body** (States stored as their body, below): a second copy would cost 8.4 KB per independent thing and 0.16 KB per dependent one, at every node.
- **The record rides in the own-secrets rotation** (The record in the rotation, below): one commit and two signatures fewer per independent thing. Content cannot join it: a commit is of one kind (spec/commits.md §2), and role commits travel as certificates under other sync IDs, where content would leak. So an independent thing made with content is two commits (a minted actor, made without, is one).
- **Dependent things**, engine rows only: 1.6 KB is the commit record (789 B, of which the header is 357 B: three aspect entries with their delta hashes, the delete-key commitment, blind and signatures), the metas row (255 B) and reference rows (178 B). The sync store's sealed blob and entry add as much again (Survey).

## Open
- **Fewer KEM keys held** (Tess: each is fine to do where a worker finds it works and is worth it; she doubts keys are where most bytes go, so measure first). The four KEM keys are half of what a reader of an independent thing downloads and, after its first grant, stored twice (the commit record, and a `keys.0` state holding two bodies whole).
  - **Store them once** after the first grant: about 6.7 KB per independent thing, no design change.
  - **Keep them from those who never seal to the thing**: only a granter sealing a box to a thing needs its KEM keys; judging its writes needs none. Matters more if a sync unit carries the evidence for every actor that could write in it (issues/actors-one-mechanism.md).
  - **Only things that hold roles publish them.** A KEM key is sealed to in two cases: the thing is a holder (accounts, a tag holding roles on its notes, a link's K), or it takes external fires (an inbox, sealed to its read key). Every other independent thing publishes four keys nobody seals to: each shared note, chat and document, the notes of a shared tag. Declaring holder kinds at minting restricts "anything may hold a role" and is against promotion being implicit. Decided by Tess (issues/external-signals-taken-by-default.md): being granted roles by a non-admin is an unusual property a thing's admins turn on (accounts, orgs; little else). A thing has KEM keys once its admins make it a holder or externally grantable; a grant to a thing not externally grantable, by someone who does not administer it, is refused, never left waiting. So most independent things (every shared note, chat and document) publish none.
  - **Roles sharing a key while their holders coincide**: up to 3.6 KB for a thing with one level of holder; a split when a lower holder first appears. The likeliest to add states.
  - Not wanted (Tess): one ML-KEM key per thing with an X25519 key per role. It saves about 3.5 KB and leaves the separation of roles inside the thing resting on the classical key alone: a wrinkle in the security posture for bytes.
- **CPU: sync-step verifications** (14 per independent make at the maker, 15 at the second node, constant in what is held): the new sync ID's steps verified again at each read. A verified-step memo keyed by step ID would make it one; about half a millisecond per make.

- **Per entry, per sync ID a blob is under** (spec/wire.md §5, §11.2): blob ID, wrap and stamp travel and are stored beside every blob in every stream (measured in the Survey: the `E/` row is 224 B, the frame about 170 B). Candidates there (12, 13); one stamp over many entries does not pay (Survey, Not candidates).

- **Tess, for the slimming work**:
  - A small commit should be one signed chunk of bytes per sync unit. Today it is one blob (header, the signer's signature, an account's sealed inner signature, sections) plus an entry with a second signature, the stamp. The two serve different readers: the commit's signature is inside the ciphertext for readers; the stamp is for nodes keeping the sync ID unread, which must not learn who wrote. Ask whether one signature can serve both, or one stamp a batch.
  - **Where the data is smaller than what points at it, embed the data**: a copy in every place beats the pointer however many places there are. Seen so far: a state row of 66-70 B naming the commit that holds a 28 B value (States stored as their body, below, wins only above that size); a 32 B delta hash in the header for a delta shorter than a hash; two reference rows of about 89 B for a 15 B tid; a 57 B wrap for a 32 B key.

- **Delete keys per commit** (Tess asked; ideas from reading notes/delete-keys.md, none studied): each delete level a commit's deltas call for costs a `[level, key]` in the header (about 35 B) and a blinded commitment in the blob's prefix (33 B), plus one 16 B blind per commit: about 85 B with one level, 150 with two (the author-or-admin default), 220 with three. Chunk, tree and page blobs carry the commitments again. Candidates:
  - **Name the key, do not carry it**: a reader already holds the admin delete key (the delete base's `keys.0`) and the author's (its signing key or chain); the header could say which epoch's in a byte or two. About 32 B per level.
  - **No level-1 commitment where it equals the sync ID's**: admins of the sync ID's thing already delete at nodes keeping it unread by the sync ID's delete key; a blob of a thing whose delete base is that thing lists the same right twice. About 68 B per such commit.
  - **Derive the blind** from the blob key, as linked blobs already do (the link blind): 16 B.
  - **One blinded commitment per author within a sync unit** (Tess: yes): about 33 B a commit. A node keeping the unit unread can then tell which of its blobs one author can delete; across units the blind still differs, so nothing links an author's blobs from one unit to another, which is what the blind exists to prevent (a node keeping units unread, with any contact's help, linking an author across them).
  - Hashed tokens in place of signatures under blinded keys were decided against by Tess (a writer that is no admin could not list the admin level).

## Rejected
- **No history boxes in a newborn's own-secrets rotation** (about 800 B). They are not empty of use: keysets never list derived epochs (spec/crypto.md §4 Lists), so the history box is what supersedes them; every later holder boxed at the first own epoch opens the rotation commit itself (wrapped under the derived epoch, §5 Who wraps under what: its keysets, boxes, record and `sync.0`) by the derived roles secret that history carries, and a grant writes again only what live entries list or the writer holds as superseded; and a node that wrote under the derived secret before the rotation reached it (TLA Depth0 `Plain`, `dhist`) is read through it. Dropping them needs a "first rotation supersedes its derived epochs" rule and grants carrying the derived secrets anyway, so the bytes move into every grant. The roles-model has no first-rotation notion (custody's thing t starts at its epoch 0), so no search applies.
- **The account root's ticket in the making commit** (osis path, about 640 B downloaded and 1 KB stored per independent thing held outside the root's unit). Same author, so signing is no bar; the bar is order: the ticket duty (`flows::inbox::write_account_ticket`, driven by sync's account-ticket effects over the closure feed) reads how the node closure enters the thing (`entered_outside`), which holds only once the making commit's strong applied and the closure settled at the transaction's end. Folding it in means predicting the closure for things made in that transaction: a special case of the duty.

## The record in the rotation
- **Rule** (spec/permissions.md §3): a thing minted with an account as admin by a commit writing content on it carries its record in its own-secrets rotation (`write::independent_first`), and so does `Engine::mint_actor`'s actor. `rotation::own_secrets_new` judges the creation as its commit would, holds the record ahead of the commit (`apply::atomic::learn_record`, timelines updated) so the rotation is built exactly as for a held dependent thing (derived epochs, holders by the record edge, the mint admin's own secrets first), then the rotation mutation `create`s it. `commit_or_build` refuses a create only where a minting is held or the held record differs, so a record held ahead passes once. An expiring first write keeps the record alone with its expiry (a role commit never expires).
- **Not for a link's K, nor a thing made without content** (`Engine::create_with_admin`): their record goes alone, the rotation after. K's readers are its redeemers, who read K's sync ID by entry boxes at its own epochs and never hold the derived one the rotation is wrapped under; a node paired later reads K by the account's holder piece under D (notes/sync-facade.md), untried with K's record moved into the rotation. A thing a records-only commit makes becomes independent at the transaction's end, which lets a maker make it independent itself first (K's sync ID listing L).
- **Who reads it**: the rotation is wrapped under the derived epoch it supersedes (spec/crypto.md §5), so the record section opens for the mint admin's holders and holders granted with history, not for a ticket's, a link key's entry-box, a cut's or a sync-only holder's. They take the record as a record blob: `Engine::records_of` counts a closure body as carrying a record only where a minting of it gives no epochs (`minted_dependent`), as spec/permissions.md §4 Logging certificates counts a rotation's blob only where it opens under the newest read epoch.
- **Rejected**: the record riding with the first content commit instead (the rotation would pend unjudgeable at every receiver until it came, making the rare pending path the common one, and a thing without content would need the record commit anyway).

## States stored as their body
An aspect unit's state is one of: empty, whole (`state::encode`), paged (`pages::open`), or `[2, commit ID]` (`state::Stored::Body`): the state is that commit's part on the aspect, as its record holds it. An independent thing's `keys.0`, `secrets.0` and `sync.0` states and most `created.0` and content states are one body each, so they cost a 66-70 B row instead of a second copy.
- **Rule**: at each transaction's end (`Tx::settle_states`, before the index persists), every unpaged state written in it (`Core::written`) is stored as a body equal to it that is held whole (not a leftover) and valid: the one it names already, else the aspect's newest (`by_aspect`); otherwise whole. Equality, not reasoning about which writes could make them differ: whatever normalised the state (value-less strips, a snapshot's copies, a dropped char), a reference reads exactly what was cached. Writers (joins, rebuilds, covered drops, strips, purges) write whole as before; one decision point, so no writer has a special case. Cost: the body's decode (`Core::decoded`, per record write) and a compare per written state, O(state) as the write's encode already is. Paged states stay paged: their point is reading a page, and a reference reads the body whole.
- **One reader**: `Tx::load_lazy` resolves it (`apply::stored_fragment`: the record's part, decoded once per record write). Every state read (cache misses, an open's `sync.0` and `account.0` states, the index check) goes through it.
- **A body leaving its record** (`Tx::put_commit` without a part the index holds whole, `unindex`): `Tx::pin_states` first reads each state naming it into the cache and notes it written, so the transaction reads it as before and `settle_states` re-decides it. A valid body's drop rebuilds or rewrites its state anyway (shredded); where it does not (forgetting keeps role-class states, a part set missing again), the state is stored whole from the cache. So no stored reference names a body not held.
- **Shred**: a reference holds no content, so dropping or purging its body leaves no copy in the state; the drop's rebuild writes the unit shredded as before (path rotation covers earlier whole versions). `drop_aspect` (destroy, forget) removes the unit. The covered-drop page rewrite touches paged states only; an unpaged covered drop rewrites whole, then settles.
- **Index**: a reference names a record, not an index row, so a rebuild of the index leaves it valid (rejoined states settle like any write). `apply::check_states` (debug) reads each checked state from the store through the reader, not the cache, against a rebuild from the held bodies.
- **Rejected**: deciding in each writer (the apply joins before its record is stored, so the body is not there yet); a second store of states; references for paged states.
