# Small suspects and untested rules from the review since the sync rewrite
> Summary: Leftovers of the review of everything since the sync rewrite, each too small for an issue of its own: rules with no test that fails without them, and suspects not reproduced. Each is a hand-written test first; a fix only if it fails.
> Priority: low
> Tags: tests, engine, keys, security

Rules with no test of their own:
- **Seal skips KEM-less keysets** (`rotation/kem.rs`; KemKeys.tla `KK_fallback`): extend `tests_kem::kem_key_due_ends_a_lockout`: before KEM key due, a rotation leaves M out and never seals at the older keyset.
- **Left-out causes**: no test fails if `rotation::members` checks the edge before `writes_keyset` (a removal rotating in the same commit stands as a rotation, LeftOut.tla `LO_rot`).
- **Dependent box, demoted admin**: an admin's step and box with no keyset, the admin demoted after the plant, behaves as spec/sync-set.md §2 says (the `sync.0` write judged at its point stays valid), but no rule reconciles boxed and unboxed nodes (the planted epochs are never established, so nothing re-seals). Only demotion before the plant is tested (`tests_planted`). `engine/secrets.rs` `own_record`, `stepped`.

Suspects:
- **The public's role wherever held** (`rotation::lost::role_here`) also feeds `may_take`/`readable` for the node's own sealed boxes, so a public grant whose removal the node lacks could keep a removed reader's sealed secrets. Harmless if a role through the public gives only open boxes.
- **A step's `since`** (`sync_ids::steps` `Recorded::of`) is the current write's stamp: an admin re-putting a step entry later leaves commits stamped in between miskeyed for good (hostile admin only).
- **`take_offer` ingests before refusing** (`flows/offers.rs`): an offer giving this node no role has its records and commits taken first, held until the pass ends if released at all.
- **`Account::nodes`** (libs/account) lists every write or admin holder of A (a client's thing, a realm) as a node; a removed node keeps `settings^.0` naming A, so `Account::of` still says it acts for A.
- **Any writer of A may move A's inbox** (a card's `since` is bounded by its write's `ts`, and any later move undoes it): for a realm that is every write member. Design, not a bug; decide whether moving the inbox should need admin.
