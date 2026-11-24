# Build: left-out records carry their causes
> Summary: build spec/crypto.md §4 Left out as specified (design: notes/holder-actors.md, Left out; model LeftOut.tla): a record names the commits that blocked its keyset, they travel carried, it counts only while one stands, and a rotator of M rotates for a counting record of a current keyset. Fixes the lockout of an honest holder actor once a record's cause turns invalid (reproducer `rotation::tests_members::repro_left_out_on_an_invalidated_rotation_spec_crypto_4`).
> Priority: normal
> Tags: engine, security

Property violated today: every holder of G with key access ends boxed at G's current epochs (spec/permissions.md §3). A record made for a cause that later turns invalid (a rotation of N below M invalidated by a concurrent demotion of its rotator, a departure by a concurrently demoted admin, a side switch) keeps M out of G for good; so does a record of a current keyset whose only rotators judge it by order. LeftOut.tla `LO_inv_old` and `LO_ign_old` fail `Live`; the specified rule passes (`LO_inv`, `LO_ign`).

## Change
- Wire and schema: keyset field 6 `left_out` becomes `map<weak, map<epoch, set<blob>>>` (spec/wire.md §7): per M, per recorded keyset, its causes' commit IDs. `schema/core.osis` `left_out 6` and its doc line, `osis_keys::aspects`, `produce::rotate_leaving_out`, `LeftOut` (per keyset: epoch to cause IDs), test vectors (`core/test/vectors` schema subject).
- Causes: `rotation::blocking` (and the box walk under it, `blocked_epoch`) returns, beside its `Block`, the commits it read per spec/crypto.md §4 Left out: a departure's newest edge write the covering epoch must name (Covers; `Departure::newest_needed`), a stale box's superseding keyset's rotation commit, a keyless grant's edge write. `rotation::members::left_out` records each current keyset of M blocked at the rotator with them, joining causes with A's current records.
- Carried: `rotation::carry` logs each recorded cause (its parts on its own thing, as a certificate copy with evidence by the ordinary rule); Held keyset for A's keysets: a keyset of A recording causes counts as not arrived until each is held (as for carried demotions).
- Effect: `left_out_at` returns only records with a cause that stands at the node (held valid; a departure's holder still departed there, not the node's own; a grant still keyless). A keyset M is left out at is blocked by a box (`blocking`), so Seal leaves M out at it; `osis_keys::seal_keyset` / `candidates` lose the left-out argument: delete `Keysets::past` and its order fallback.
- Re-key: replace `left_out_for_good` (both, in `osis_keys::members` and `rotation::members`) with "M is left out of A at a current keyset of M" at `Due::PassEnd`, keeping its holder-with-key-access condition.

## Tests
- Un-ignore `repro_left_out_on_an_invalidated_rotation_spec_crypto_4`; add its departure twin (a removal from M by an admin demoted concurrently) and a regrant of the departed party ending a record.
- A co-writer holding A's recording keyset holds the cause: a keyset of A whose cause is withheld counts as not arrived (fails with the carry off: the co-writer re-seals M at a keyset made before the departure, as `LO_nocarry`).
- A record of a current keyset whose rotator reads M only by order makes it rotate (`LO_ign`); a hostile record naming a standing departure and a covering keyset costs one rotation of M per record (rework `hostile_record_forces_one_rotation_per_rotation_of_a_spec_crypto_4`).
- Delete or rewrite what tests the removed rules: `osis_keys` `seal_keyset_past_left_out`, `left_out_past_by_order_after_its_record`, `left_out_for_good_needs_no_candidate_and_no_current_record`; engine `left_out_for_good_world` and its users.
- Run `core/test/tla/run.sh leftout` (the model is landed); the rotation property tests (`tests_property::rotation_holds_*`) at their default size.
