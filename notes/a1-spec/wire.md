# A1 draft: spec/wire.md
> Summary: Draft spec text for stage A1 (not in spec, not built): spec/wire.md §4's header with `signer` and `path` in place of `author` and `actor`, the hashed path per thing, the purge-author index, `remains`, what is signed and what a decoder rejects; with the §2, §5 and §12 lines that change beside it. Map and status: notes/a1-spec/README.md.

Replaces, in spec/wire.md: §2 the constants table (one row added); §4 the grammar block, header fields 1, 2, 8, 11, 12, 14 to 18, the Commit blob plaintext's `Section` bullet, Inline or link, Commit ID and the commit signature, Inner signature's first sentence; §5 the header-list commitment line; §12 the Header line. Everything of §4 not quoted here stands as it is (fields 0, 3 to 7, 9, 10, 13, Aspect fields, the merge signatures, List tree, the reader and `Part` bullets, the bad-input list).

## 2. Constants
### Fixed by the format version
One row added to the table:

| constant | value |
|---|---|
| MAX_PATH_THINGS | 64 things listed in one stated path (§4) |

## 4. Commits
```
Header    := [version, signer, path, kind, ts, form, expires, aspects,
              purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation, reseal, remains, flags?]
Path      := [index, tid*]                 ; the purge-author index, then the listed things A1..Ak
Paths     := Path | [hash, hash+]          ; one path for every thing written, or one hash per thing
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
0. `version`: stands.
1. `signer`: tid of the key actor whose key signs the commit (spec/permissions.md §1): an account, or a key actor other than an account signing as itself (a node only for its own node thing's aspects, spec/permissions.md §1). The commit is by its signer (spec/commits.md §1).
2. `path`: the paths the commit states, one per thing it writes (Path, spec/permissions.md §1), as `Paths`:
   - A `Path` is the purge-author index i then the tids of the listed things A1 … Ak in order, 0 ≤ k ≤ MAX_PATH_THINGS: no tid twice and none equal to `signer`; i ≤ k (0 names the signer, j the thing Aj: spec/permissions.md §6); else bad input.
   - **One for all**: `path` holds one `Path` (an array whose first item is a uint): every thing the commit writes is written along it.
   - **One per thing**: `path` holds one 32-byte hash per distinct tid of `aspects`, in the order of each tid's first aspect, at least two (an array of byte strings; another count is bad input). The hash of thing T's path is `kdf("path", salt, canonical bytes of the Path)`, where `salt` is 16 bytes; T's sections carry the salt and the Path (`Section`, below). A writer uses this form iff the things it writes do not all state one Path, and draws each salt at random.
   - A rotation (field 15) and a seed re-seal (field 16) state one for all, `[0]`: the signer writing itself.
3. to 7.: stand.
8. `purge`: `[PurgeItem*]` sorted by canonical bytes, distinct; empty when there is no purge request. `[tid, ak]` names every delta on that aspect of every commit with a smaller `ts`; `[tid, ak, author]` those of them whose purge author is `author` (spec/permissions.md §6); `[tid, ak, ts, source]` the delta on that aspect of the commit stamped `ts` whose own writes are `source`'s (spec/crdt.md §2.1: 31 bytes, a session; 32, a commit-form commit's ID; else bad input), one commit per stamp and source on an aspect (spec/commits.md §5 Purge); on `created.0` only `[tid, created.0]` (it names every minting, spec/commits.md §5 Destruction).
9., 10.: stand.
11. `keys`: `[DeleteKey*]` sorted by canonical bytes, distinct: the delete keys of the commit's deltas (spec/crypto.md §7), `pk` a valid Ed25519 key (§1, spec/crypto.md §1), at level 2 one per distinct purge author the commit's paths name; a key no aspect lists is bad input.
12. `frontier`: `Opt(frontier)`, the frontier value (spec/data-model.md §9), exactly `{0: set<32-byte commit ID>}`, inline or linked; present iff the commit is a role commit carrying an explicit removal or a lowering (spec/permissions.md §5.1 Frontier; a writer rule: a receiver checks only that it sits on a role commit). Any other value there is bad input.
13. `ephemeral`: stands.
14. `epoch`: `Opt(epoch_id)`, the epoch an account signer signs at (spec/crypto.md §9; 32 bytes: the minting plain rotation's commit ID, a merge's ID, 32 zero bytes for the first epoch); present iff the signer's creation record marks an account, else bad input.
15. `rotation`: `Opt(Rotation)`, present only on a role commit whose signer is an account (else bad input): the new epoch's signing key and KEM key (spec/crypto.md §3); the epochs it supersedes, ascending, distinct, the header's `epoch` among them (else bad input); `path` the one-for-all `[0]` and a `keys.0` delta on the signer (else bad input); the tips it names (a merge certificate, spec/crypto.md §9 Merges: every tip but the header's `epoch`; empty for a plain rotation), ascending, distinct; a merge certificate supersedes exactly the header's `epoch` and its names, takes nothing, and has `revokes` false and `devices` empty (else bad input); the rotations it **takes** (spec/permissions.md §5.4: carrying removals from D its maker took, not on its line; every node holds the rotation only once these are, and only the account's nodes read it further), ascending, distinct; `revokes`, whether it removes a device from D (spec/permissions.md §5.5 Revoked: what every reader reads of its membership changes); `devices`, its membership changes of D sealed (spec/crypto.md §9, Roster), empty when it carries none; `list_root`, 32 bytes, the root of its list tree (below); its seed boxes (spec/crypto.md §9, Custody), each a 16-byte `tag` and a sealed box (§7) of a payload of 32-byte seeds, at least one, ascending by tag, distinct (else bad input). A plain rotation's commit ID names the epoch it mints; a merge certificate's epoch is its merge ID.
16. `reseal`: `Opt(Reseal)`, a seed re-seal (spec/crypto.md §9, Custody), present only on a role commit whose signer is an account, `path` the one-for-all `[0]`, whose `rotation` is absent (else bad input): the signing key of the epoch whose seed it boxes and its seed boxes, as `rotation`'s, at least one, ascending by tag, distinct (else bad input).
17. `remains`: `Opt(tid)`, the holder of the remaining admin edge the commit's edge writes rely on (spec/permissions.md §1, The last admin); present only with `kind` 1, an aspect `roles.0` in `aspects`, and the adminless bit (field 18) clear; else bad input.
18. `flags`: uint, present only when nonzero. Bit 0, own cover: its writer's own cover at a removal or an account's rotation (spec/permissions.md §5.1, §5.5, Own cover), only with `kind` 2 and no `ephemeral`. Bit 1, adminless: the adminless mark (spec/permissions.md §2), only with `kind` 1. Other bits are reserved and MUST be zero. A `flags` of 0, a reserved bit, or a bit on a header it is not allowed on is bad input.

- **Commit blob** plaintext: `CommitBlobPlaintext`: one blob carries the whole commit, every part sealed to its thing's readers (spec/sync-judgement.md §1).
  - A `Section` holds the parts of one thing: `[ai+]` the aspect indices of its parts, ascending, distinct, each with a part inside; `[chain*]` the thing's derivation chain (spec/crypto.md §3) as the writer knows it, nearest first (empty for an independent thing or a key actor; at most `MAX_CHAIN_DEPTH`, no tid twice: else bad input); `ciphertext` = XChaCha20-Poly1305 of the canonical `Contents` under a fresh random 32-byte section key, nonce 24 zero bytes (the key encrypts this one plaintext and nothing else), AD = the commit ID; `wrap` = a random 24-byte nonce `||` XChaCha20-Poly1305 of the section key under `kdf("section", read secret of the thing)` (its own, or derived from its mint admin's by tid, spec/crypto.md §3) at the newest epoch the writer holds (a section of a commit giving read epochs under an epoch they supersede, spec/crypto.md §5), that nonce, AD = the commit ID: 72 bytes. A thing's role parts (`roles.0`, `keys.0`, `secrets.0`, `vouches.0`) go in a section of their own whose `wrap` is under `kdf("section", roles secret)` of that epoch (spec/crypto.md §4, Roles secrets). Sections sorted by their first `ai`; an aspect in two sections is bad input; zero sections is allowed (every delta purged). A copy (per-sync-ID or certificate, spec/sync-judgement.md §1) is one section of its parts, with an empty chain, its `wrap` under `kdf("section", blob key)` in place of a read secret: whoever opens a wrap of the blob reads it.
  - `Contents` holds the thing's `Salted` iff `path` is one per thing, absent iff it is one for all; every section of a thing (its role section and its other section alike, and each copy of its parts) carries the same `Salted`. A section whose `Salted` is absent where `path` is one per thing, present where it is one for all, or does not hash to its thing's entry in `path` holds no part of the commit: its parts are as bytes that do not match the header's delta hash (spec/commits.md §4).
  - The reader bullet ("A reader tries, per section, ...") and the `Part` bullet stand.
- **Inline or link**: `aspects`, `purge`, `keys` and the frontier are each inline iff their canonical encoding is at most `CHUNK_THRESHOLD` bytes; otherwise the position holds a LINK value (`Opt(LINK)` for the frontier) to a chunk tree (§6) of that canonical encoding, its content hashes keyed by the header's **list key** `kdf("header list", dedup secret of the header's signer, skeleton)`, the skeleton being the header's canonical bytes with each position that goes by link holding `[]` (so a list's tree serves one header only). A decoder rejects an inline list above the threshold or a link to one at or below it or above `MAX_LIST_BYTES`; a writer refuses such a commit. Header-list chunks carry the commitments of §5: every link of a list's tree names, as its delete keys, the signer's level-2 delete key alone (spec/crypto.md §7); any other is bad input.
- **Commit ID** = BLAKE3(canonical bytes of `Header`). The signature is the `signature` value of the signer's key (an account's: the signing key of the epoch the header names) under `"osis v1 commit"` over the digest below. The commit ID covers `signer` and `path`; one per thing, each thing's `Path` is bound by its hash there and its `Salted` sits in ciphertext whose AD is the commit ID.
- The commit signature of an account signer's commit signs BLAKE3(commit ID ‖ `inner` ‖ each merge signature) (spec/crypto.md §2); every other commit's signs the commit ID.
- **Inner signature** (spec/crypto.md §3): `inner` is present iff the signer is an account (else bad input); the rest stands.

## 5. Blob framing
The commitments bullet on header lists reads:
  - a chunk or tree node of a linked header list (§4) carries one group holding the commitment of the signer's level-2 delete key (spec/crypto.md §7) only; its expiry is the commit's `expires`.

## 12. Decoder limits
The Header line reads:
- Header: each inline list at most `CHUNK_THRESHOLD` bytes, each linked one at most `MAX_LIST_BYTES`; a `Path` at most MAX_PATH_THINGS listed things. The rest of the line stands.
