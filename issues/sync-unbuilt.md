# Parts of the rebuilt sync not built yet
> Summary: The parts of osis-sync and its engine facade that are stubbed, answer `NotBuilt` or are missing, per module, each with the spec rule it leaves unmet; wire strings and the link format that differ from the spec; larger gaps have their own issues (listed at the end).
> Priority: normal
> Tags: sync

Each line: what is missing, what it costs now. The module notes (notes/sync-*.md) point here.

## session
- The account's rotations in a Prove (spec/sync-opens.md §2): `Engine::prove_rotations` and `take_rotations` answer `NotBuilt`, so none are sent and those received are not taken; a verifier behind on the prover's account rotations judges its proof at an old epoch.
- Closing a connection where this node came to act for an actor it did not prove there (spec/sync-opens.md §1); the dials redial at once instead.
- The node-wide bound on what served connections hold (spec/sync-transport.md §5 Served connections: requests waiting for the bound's room, reading paused, the largest holders closed); needs `Sessions` to hold answers back. Each connection is bounded alone.

## opens
- Records' named actors (spec/sync-opens.md §3: a record is honoured only while a proven actor it names is known here now) are judged at a connection's proof alone; a live connection keeps its record when the actor stops being known.
- Static entries claimed in the walk's tests (`Tested::Static` always has no step).
- A reader's walk tests only its recorded steps' credentials, not the sync key of each sync secret it holds (spec/sync-ids.md §6 Test): a node keeping S unread granted at an epoch no recorded step bears is never opened (`keep::a_store_granted_again_after_its_removal_reaches_the_head_spec_sync_ids_6`, ignored).

## store and streams
- Fetching an unjudgeable body again (spec/commits.md §4 Unjudgeable, spec/sync-judgement.md §3 Dropped bodies): needs byte-less entries and a refetch path; until then an awaiting entry keeps its bytes (notes/sync-store.md).
- Refused (spec/sync-streams.md §4): a refused entry is not offered again once the refusing node's head moved. The genesis Register goes out at a store source's open before anything of S is served there, so entries reach a head; a genesis refused for now (4, 12), or any later head move, leaves the entries refused meanwhile untaken there until a new stamp.
- Relay-only entries; the engine's linked blobs (`Engine::wants`: pages and header lists before apply); bundle import (`Streams::import`); `Rank::Never` (a keyset without history: the facade has no call for it).

## read
- `SrcView::role_unheld` is always false: deletes toward a source do not wait for a role commit it lacks.
- Level-key deletes (freed links, spec/sync-compaction.md §1); a peer's entry counting as lacking for its wrap (Duplicates, spec/sync-ids.md §6 Wraps).
- HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does) is the engine's `fall_mark`, untested end to end.

## inbox
- A promotion's chain (`held::log_chain`: not built; the engine seals certificate copies, `sync_bodies`).
- Stranded and Suspect are answered Ok and acted on by nobody (spec/permissions.md §4: the stranded holder's re-seal, the suspect repair).
- Clearing at sources keeping S unread: needs streams' `known` to carry each entry's deposited flag and blob size.
- A decline stamping in place.
- Opens' members are not stamped, so a source's step moving reaches Register only through its next join.
- No admin issues a step (spec/sync-ids.md §6 Steps; `Engine::issue_step` is called by nothing): a rotation never reaches a path, so a holder granted after one strands at the genesis registered there (the same ignored test).

## status and API
- Covered by a snapshot at a source (spec/sync-status.md §2): needs the engine's covering snapshots of a commit; a body a source dropped under a snapshot before showing it never counts (an under-claim).
- `caps()`/`set_caps` in the osis API over `caps^.0` (the engine reads `caps^.0`; nothing writes it but a raw write).

## facade
- The complete-pass want of a role found gone (spec/permissions.md §2, which `lost_leaving` waits on).
- Nothing calls `history_complete` (spec/sync-status.md §3) from the API.

## Wire differs from spec
- Domain and kdf strings in osis-crypto keep the old words where spec/crypto.md §2 and spec/wire.md §8 name new ones (`"osis v1 label id"` for `"osis v1 sync id"`, `"osis v1 label open"` for `"osis v1 sync open"`, `"osis v1 label register"`, kdf `"label sync"` and the other `LABEL_*` for `"sync key"`, `"sync claim"`, ...): a node built from the spec cannot open, verify or derive with this one. Rename with their vectors (issues/deprecated-terms.md, label).
- osis-label's link carries a `hosts` list between K's sync ID and the peers that spec/wire.md §10 `Link` does not have.

## Own issues
issues/reseal-under-own-epoch-leaks.md (Sync side), issues/sync-walk-reopen.md, issues/sync-link-first-contact.md, issues/group-source-hand-off.md, issues/sync-pending-unbounded-paths.md.
