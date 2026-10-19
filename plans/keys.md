# Keys crate: epochs, boxes, history, covers rule, rotation and re-seal planning, /keys and /secrets
> Summary: Implement spec/crypto.md §3–§5 and spec/permissions.md §3 in `osis-keys`: per-role epochs with forks, the `/keys` and `/secrets` aspect contents, grant and rotation box production, history boxes, opening boxes with any held key, derived secrets for plain things and key actors, the departure and covers rule, the rotation planner (what must rotate when a member departs, transitively), re-seal production, which epoch to wrap under, token secrets per level, label role keys for a server's head.
> Tags: crypto, permissions, security, tests

Crate: `osis-keys`. Depends on: osis-core, osis-crypto, osis-schema (core aspect types) or local structs reconciled later, osis-perm (who may rotate, rosters). Unblocks: node-core (opening blobs, token secrets), membership-flows, node-sync (wrap epoch choice, label keys).
Spec: spec/crypto.md §3–§5, §7; spec/permissions.md §3; spec/sync.md §2 (label keys from newest epoch), §5 (re-registration trigger). Notes: notes/crypto.md, notes/permissions.md (Keys section: why write+ rotates, forks, re-seal trigger, stale /keys window), notes/sync.md (rotation commits wrap under the superseded epoch). Spec trumps this plan.

## Deliverables
- `Epoch { n, nonce, suite }`; per actor per role: the set of held epochs with secrets, which are superseded (by held rotations), current and newest (greatest n, ties lowest nonce); forks kept.
- `KeysAspect` (`/keys`: per role {epoch, kem_key}; key actor single entry; inbox; deposit seed) and `SecretsAspect` (`/secrets`: boxes keyed (member, role, epoch), history keyed (role, epoch)) with the delta semantics of §4 (a rotation of r writes r's new boxes and removes r's boxes at the epochs it supersedes, nothing else).
- Box production: `grant_boxes(grantee, roles, current epochs per role, grantee keyset)`; `rotation(roles, members per role incl. owner, fresh secrets, rng)` → new epochs, boxes (sealed to each member's KEM key for that role; symmetric where the writer holds the member's secret; key-actor members get one box at the highest role carrying every role), history boxes (every earlier distinct secret incl. forks), keyset entries; `reseal(member, roles)`.
- Opening: given my private keys (KEM per role per epoch of my actor, key-actor single key) and held `/secrets`, recover each role's secret at its newest epoch, then older ones via history boxes; a `SecretStore` trait for persistence (store implements).
- Derived secrets: plain thing `kdf("thing <role>", owner secret, tid)` with the owner's epoch; key actor role secrets from the seed; "give a thing secrets of its own" = rotation from the derived epochs with history boxes carrying the derived secrets.
- Departures and covers rule (§4): a departure (removal, demotion below r, `until` passed on the corrected clock) of M from A; an epoch covers it iff it holds no box for M (or, for a departure inside M, M's box names M's newest keyset epoch the node holds); `may_encrypt_under(epoch)`; "rotate first" decision; the rotation-commit wrap exception.
- Rotation planner: given a departure of M from actor A and the held graph (what A owns, targets of A's edges, transitively; which of those have secrets of their own), the set of (thing, roles) requiring rotation; which of them this node may rotate (perm: write+ rotates ≤ its role); the "before I next encrypt under it" gate; eager option.
- Wrap epoch choice for an upload (newest read epoch; a rotation under the newest epoch it supersedes); label role keys for the epochs a server's head registers (osis-label derives the keys; this crate picks the epochs).
- Token secrets per level for a delta (admin secret of thing, write secret above the author, thing write secret) by retention; trying each held epoch of a secret when deriving tokens.
- A removed node drops the actor's secrets and what it can no longer read (list what to drop; store executes).

## Steps
- [ ] Epoch model, aspects and their delta rules (fork merge test: two concurrent rotations' boxes both survive; members hold both secrets).
- [ ] Box production/opening/history; sizes (≈1.2 KB per sealed box; symmetric 49 B + epoch).
- [ ] Derived secrets; own-secrets switch; covers rule with the notes scenarios (lost device → owner rotation → owned thing's derived epoch stale; grant raced by rotation → re-seal trigger; rotation held without the removal → heals when the removal arrives).
- [ ] Planner over an abstract graph trait; wrap epoch choice; token secrets.
- [ ] Vectors for `/keys` and `/secrets` encodings once protocol-spec fixes them; proptest: a member departed before epoch n+1 can open nothing at ≥ n+1 given only its boxes; every current member opens the newest epoch of each of its roles after a rotation.

## Done when
membership-flows and node-sync use this crate for every key decision; notes/crypto.md and notes/permissions.md updated with the planner's shape. Delete this plan.

## Progress
