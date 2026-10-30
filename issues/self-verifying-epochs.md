# Self-verifying epochs: an epoch's ID is derived from its secret
> Summary: Design note (go): make each epoch's nonce a KDF of its secret, `kdf("epoch", s, actor || role || le64(n))`, so every box, history entry, entry box and keyset is checked alone, in any order, by recomputing its epoch. That closes inverse poisoning, history poisoning, forged entry boxes and equivocation, and removes the "first keyset" record, the rotation box hashes, unverified and multi-candidate lists, and the reopen-on-refute paths. It does not stop planted epochs, huge n, false supersession or junk keysets seen by non-holders: establishment, caps and headroom stay. No migration.
> Tags: security, crypto, keys

## Problem
Today an epoch is `(n, random 16-byte nonce)`, so nothing ties an epoch to its secret. Every source that claims "s is the secret of e" has to be trusted, or checked against some other record. That is why there is a growing pile of first-wins state: `EpochInfo::keyset` (the first keyset recorded), `EpochInfo::history` (the hash of the first rotation's history box), `EpochInfo::unverified`, and `reading` with one candidate per author. Each first-wins record depends on order. The latest problem is issues/keyset-first-writer-dos.md: a writer re-publishes a bogus keyset at epoch E, a late joiner records it first, and then refuses its genuine box at E for good.

## Proposal
**Epoch ID.** `nonce(actor, role, n, s) = kdf("epoch", s, actor tid (15) || role byte || le64(n))`, either the first 16 bytes (as now) or all 32 bytes (recommended, see Costs). An epoch is still `[n, nonce]`. The rotator draws s at random and computes the nonce; it no longer picks a nonce.

- **Why the secret and not the public keyset.** Holders of s check either one, at the same strength. Only a non-holder would gain from hashing the keyset `(kem_key, delete_key)`: it could check that a `/keys` keyset matches the epoch it names. That buys nothing, because a writer who wants to publish junk keys just names a new epoch whose ID matches the junk (n+1, any nonce), and a non-holder cannot tell that epoch from a real one. Hashing the keyset would also cost an ML-KEM keygen plus a delete-key derivation (about 60 µs) per check instead of one BLAKE3 call, and would tie epoch identity to the KEM. Hashing both adds nothing. So: hash the secret only.
- **Why bind actor, role and n.** This is domain separation only. Without the binding, genuine epochs would still be safe: a secret reused under another actor, role or n is simply a new planted epoch. With it, one secret never names two epochs, and IDs cannot be linked across derived things. It costs nothing.
- **Suite.** The nonce function belongs to suite 1, as secret-to-keyset derivation already does. A later suite defines its own.

**What each artifact carries.** Every secret on the wire travels as `(n, s)`. The reader recomputes the nonce, so an entry cannot name a wrong epoch: that is a structural property, not a check someone can forget.
- `/secrets` box keyed `(member, role, e)`, AD unchanged. Sealed payload `[[role, n, secret]+]`, nonce dropped. Each item's epoch is recomputed. The item for the key's role must recompute to e, otherwise the box is bad (ignored, which also makes "stranded" a crisp signal). The symmetric form and its `epoch of s` are unchanged; `epoch of s` stays because the covers rule needs it.
- History box `(r, e)`: AD unchanged, plaintext `[[n, secret]*]`. Opening it with s_e proves the writer held s_e. Each entry names its own epoch. A forged entry can only name an epoch nobody else uses (see Not closed).
- Entry box (spec/sync.md §2): payload `[[read, n, secret]]`. The actor is the label's.
- `/keys` keyset `{epoch, kem_key, delete_key}`, unchanged. It is never a trust anchor. A holder of the epoch's secret derives the keys itself, and a sealer holding that secret uses the keys it derived. A non-holder seals to `/keys` as today.

## Attacks
Closed, in every order, with no stored state:
- **Inverse poisoning** (issues/keyset-first-writer-dos.md). W's keyset at E with junk keys refutes nothing. D's genuine box recomputes to E, and W's keyset fails against E's secret wherever someone checks it. The related `invalidated` problem has a separate cause (see step 4).
- **History poisoning** by an invite holder, a rotating writer or a removed holder. A lying entry for a real epoch recomputes to a different epoch, which is a planted epoch at most. The real epoch's secret can come from any genuine entry, box or copy.
- **Forged entry boxes** (a removed admin holding the step key). Same as history: the entry can give a genuine old secret it held, which is harmless, or a planted epoch.
- **Wrong secrets in boxes**, from invite grants, pending or invalid commits, or backdated ex-admins: these fail on sight. This also covers pending-commit secrets at real epochs, which today are why there are several candidates per epoch.
- **Equivocating writers**: a rotator giving members different secrets under one epoch. This needs a collision in the nonce: about 2^64 work with 16 bytes, about 2^128 with 32. Today a rotator can equivocate for free.

Not closed (unchanged; the existing rule stays):
- **Planted epochs.** Anyone who can write a box, history entry or entry box can make up `(n, s)`. The ID is consistent by construction, but nothing makes the epoch legitimate. Establishment still decides legitimacy: an applied valid rotation commit with its chain, a snapshot, own, fixed or derived. Only established epochs are encrypted under or put in history boxes (`held_established`). Planted epochs from pending commits still cost a trial decrypt per wrap (wraps name no epoch), so the caps stay, now counting epochs, not candidates.
- **Huge n** (item 86). The rotator chooses n freely. `MAX_FREE_N` and `within_headroom` stay, and so does issues/epoch-headroom-derived-switch.md.
- **False supersession.** A history box opened with a checked s_e, or a writer re-claiming e in a later valid commit, still adds to `supersedes` (as today for the applied state). This is bounded: such writers could rotate anyway, and the next rotation's history covers every held secret.
- **Junk keysets for non-holders.** A writer of A who publishes junk keys under a fresh epoch makes sealers to A who do not hold A's secrets seal boxes nobody can open. This is the existing writer DoS on A's memberships; re-seal triggers heal it.
- **A malicious rotator's choices**: omitted members, reused or weak secrets, grinding the lowest nonce to win `newest` among forks (it can already choose the nonce today).
- **Lost-access and pending-grant rules** (items 88, 92) and link finalization. These are about whether a node may keep a secret, not whether the secret is genuine.
- **A genuine history entry hidden by LWW.** `HistoryAlts` (try every live entry) stays. Self-verification does make a history box's content a set that can be checked. A later simplification could merge alternatives into the union of checked entries when compacting or re-sealing.

## What it deletes
Spec (crypto §4): the "holds the keyset … first such kept" paragraph, the four ways a listed secret gets "checked", the "candidate must derive the keyset" clauses, and the "kept for reading as a candidate" path for history entries and entry boxes. They become one sentence: "a secret is the secret of the epoch its `(actor, role, n)` and the nonce rule name; a box or entry naming one that does not match is ignored." Also the matching clause in spec/sync.md §2.

osis-keys:
- `EpochInfo::keyset`, `EpochInfo::derives`, `RoleEpochs::set_keyset`, `osis_keys::check_keysets` (and its calls in `SecretsWrite::applied`, `apply/atomic.rs` and `Core::ingest_secrets`' `published` argument).
- `EpochInfo::history`, `set_history`, `is_rotation_history`, the `genuine` branch of `open_histories`, and the history clearing in `unset_applied`.
- `EpochInfo::unverified` and `learn_unverified`. `Engine::learn_read_secret` becomes check-and-hold.
- `set_box_secret`, which merges into `set_secret` (the check is the recompute in osis-crypto).
- `reading: Vec<(Secret32, Unchecked)>` becomes at most one secret per epoch plus the set of pending sources it is known from (for `drop_reading_from` and forgetting). This removes `retain_reading`, the "one per author per epoch so a planted wrong one does not hide the genuine one" rule, and the multi-candidate trial loops in `reading_secrets`, `held_newest_first` and `registered_secret`.
- The candidate half of `Core::adopt_derived` (establishment stays).

Engine:
- The reopen on a refuted held secret or a newly recorded keyset (`apply/keys.rs` `reopen`, `held_count`), since a held secret is never refuted later.
- Those fields in `encode_epochs`.

Stays: establishment and `Provenance`, `MAX_READING`/`MAX_READING_PER_AUTHOR`/`UNKNOWN_AUTHOR`/`MAX_READING_ACTORS` (now counting epochs known only from pending commits), headroom, `HistoryAlts`, the covers rule, and the lost-access rules.

Free gain: a compacted late joiner's secrets of old epochs are now checked, so its own rotations' history boxes carry them (notes/crypto.md's stated cost of key-trust goes away). Such epochs count when they are established by snapshot, which they are once the snapshot keys their history box.

## Costs
- **Hashing**: one keyed BLAKE3 per secret learned, under 1 µs, next to a KEM open of about 100 µs. Nothing per blob or commit.
- **Wire**: payloads shrink by 17 bytes per item (sealed box items, history entries, entry boxes). With 32-byte nonces, each epoch in a box key, symmetric form, sealed form, keyset and AD grows 16 bytes. That is about +1.3% on a 1.2 KB box, +48 bytes on `/keys`, and history roughly breaks even. Recommendation: 32 bytes, so "one ID, one secret" is plain collision resistance at the suite's 128-bit level, with no attacker-cost argument needed. 16 bytes is acceptable if the owner prefers (2^64 work buys a silent DoS by an insider who could do louder ones cheaply).
- **Compaction**: unchanged; snapshots vouch as before. Persisted epoch state shrinks.
- **Code**: net deletion, probably a few hundred lines across osis-keys and the engine, plus spec text.

## Interplay
- **Forks at one n**: distinct random secrets give distinct IDs, as now. Every fork is kept, and history covers them all. Tie-break by lowest nonce stays.
- **Derived epochs (owner chains)**: a plain thing's epoch becomes `(owner's n, nonce(thing, role, n, derived s))`, no longer the owner's ID. Every pair, derived ones included, then checks by the one rule; the switch rotation's history entries check without `adopt_derived`, and derivation is only how a node computes a plain thing's epochs (`ActorEpochs::derived`). Code that assumed a derived epoch equals the owner's ID must be checked (`adopt_derived`, label step and re-registration matching, the delete-key search along the owner chain, `newer_than_head`). This is the main implementation risk. Members never have derived epochs, because a thing gets secrets of its own before it becomes a member.
- **Key actors**: either keep `Epoch::ZERO`, or use `(0, nonce(tid, role, 0, kdf("role <role>", seed)))` for one rule with no exception. Nobody but the seed holder ever checks it. The uniform rule is preferred but optional (11 uses of `Epoch::ZERO`).
- **Invite grants**: an invite holder can no longer lie about secrets of real epochs. It can still plant epochs (unestablished, read only) or leave the grantee stranded, and re-seal heals that.
- **Recovery and link keys**: one sealed box carrying several roles; every item is recomputed. Entry boxes are self-checking. Link finalization and redemption races are unaffected.
- **Rotation-commit identity**: a holder can re-claim E (a valid commit with E's genuine keyset). That is harmless for secrets, but `applied: Option<set>` is one slot, so invalidating the re-claim clears E's real rotation (keyset-first-writer-dos, "Related"). Fix alongside: `applied: BTreeMap<CommitId, BTreeSet<Epoch>>`. E counts as Chain when any applied valid claimant's set is established, and `invalidated` removes only that commit's entry. This removes the last first-wins slot.
- **Migration**: none (no compat). Epoch and payload formats change in place, and stores from older commits fail to load.

## Recommendation: go
It removes a whole family of order-dependent "which copy do we trust" state with one rule that each artifact checks alone. It is simpler to state and to verify, and it costs almost nothing. What it does not do (legitimacy, n bounds, supersession) stays with establishment, which is where it belongs.

Steps (one branch, gated together; steps 1-3 cannot land apart):
1. **Spec**: crypto §3 (nonce rule; derived and key-actor epochs), §4 (delete the keyset/candidate/history-hash text, add the one rule, caps count epochs from pending sources), wire §1/§7 (nonce length, payloads `[n, secret]`), sync §2 (entry box checked).
2. **osis-crypto**: `Epoch::derive(actor, role, n, &s)`. `open_box`, `open_history` and entry boxes return recomputed epochs and reject a box item that does not match its key. `seal_*` take `(n, s)`. Remove random-nonce epoch creation from rotation.
3. **osis-keys and engine**: shrink `EpochInfo` (the deletions above). Make `applied` per commit and fix `invalidated`. Derive plain-thing epoch IDs from the derived secrets and fix the derived-ID users. Format `encode_epochs` in place.
4. **Tests**: the keyset-first-writer-dos scenario in both orders (with compaction, and with parents skipping the rotation); lying history entries, entry boxes and invite boxes ignored on sight; a re-claim then invalidated keeps E's Chain. Rewrite the keyset-first, rotation-hash and unverified tests in `core/keys/tests/it/boxes.rs`. Run perm, order and sim oracles as for key-trust.
5. **Bookkeeping**: delete issues/keyset-first-writer-dos.md on landing, and update notes/crypto.md (osis-keys paragraph) and notes/permissions.md.
6. **Optional follow-up**: drop "a secret learned only from pending commits is never encrypted under" for established epochs (the secret is genuine; the source then only drives forgetting), after re-reading the item 88/92 lost-access rules.
