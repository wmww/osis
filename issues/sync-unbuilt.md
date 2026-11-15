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
- A Behind answered 4 (refused for now, spec/sync-ids.md §6 Register: asked again after a back-off) is asked again only at this node's next change of S.

## store and streams
- Fetching an unjudgeable body again (spec/commits.md §4 Unjudgeable, spec/sync-judgement.md §3 Dropped bodies): needs byte-less entries (a body counting missing is fetched again through `Streams::fetch_again`, notes/sync-read.md); until then an awaiting entry keeps its bytes (notes/sync-store.md).
- Refused (spec/sync-streams.md §4): a refused entry is not offered again once the refusing node's head moved. The genesis Register goes out at a store source's open before anything of S is served there, so entries reach a head; a genesis refused for now (4, 12), or any later head move, leaves the entries refused meanwhile untaken there until a new stamp.
- Fill order again (spec/sync-streams.md §4 Fill order, 4): a body queued as not opening keeps its last place when a read secret of S arrives; it should park under S's read secrets and be ranked again then, as the store's parked entries are (notes/sync.md Arriving early).
- An ephemeral entry a reader refused for its memory cap (`Ingested::TooLarge`, spec/sync-compaction.md §2 Caps) is not fetched again once S's held bytes drop below what they were at the refusal: it comes again only with its next listing (a new connection's join). Needs streams to keep the refusal per S with the usage then, as `room` does for a node keeping S unread.
- Bundle import (`Streams::import`); `Rank::Never` (a keyset without history: the facade has no call for it).
- A source that drops S and keeps it again (shred, then listed again) is still at the step its stream last named for a registrar that joins it again from a stored position: the source's log forgot S's events (`log_forget`), so no head event or deletion clears it there, and nothing is registered (spec/sync-streams.md §3 names no event for a head gone). Reachable by unlisting and listing the thing again at that node: it takes nothing until a registrar with no stored position there registers the genesis step. A listing from the start that names no head could clear it (`known`'s head replaced like presence).

## read
- A reader shown an entry it holds under another stamp that also verifies under its head keeps the one it holds (spec/sync-ids.md §6 Role entries: it keeps the lower, as bytes), so two writers stamping one entry under either domain need not settle on one.
- `SrcView::role_unheld` is always false: deletes toward a source do not wait for a role commit it lacks.
- A peer's entry counting as lacking for its wrap (Duplicates, spec/sync-ids.md §6 Wraps).
- Freed links (spec/sync-compaction.md §1): a judgment waiting on a node blob not held (`Engine::freed_wants`) is not fetched, and nothing calls `judge_freed`/`judge_freed_page`, so a waiting row is judged again only when its thing's next freed link is, and a start judges none; freed deletes do not wait on Role entries first (spec/sync-judgement.md §3). A row is judged once, not again at each delete sent: a body arriving later that links the blob (another writer's reuse) does not stop deletes toward store sources that show it from then on, nor un-free its bytes here (`is_freed`); the reusing author's repair is then what restores it.
- Pieces: a thing leaving a group leaves its pieces under the old sync ID (Retag, spec/sync-judgement.md §1); a non-writer's pieces reach a store source only as deposits (inbox's offers), never relayed under the writer's stamp.
- HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does) is the engine's `fall_mark`, untested end to end.
- `Live::fresh` (the held blobs it hands `Engine::seal_body`) has no World test: a mutation passing none fails no osis-sync test; the engine's `rotation::tests_reseal::facade_*` cover the contract. Cheapest found: a purge of one thing's part of a commit spanning two things, the other thing's section then logged again verbatim.

## inbox
- A promotion's chain (`held::log_chain`: not built; the engine seals certificate copies, `sync_bodies`).
- Clearing at sources keeping S unread: needs streams' `known` to carry each entry's deposited flag and blob size.
- A decline stamping in place.
- Opens' members are not stamped, so a source's step moving reaches Register only through its next join.
- A deposit-only step (a refreshed seed, no newer role epoch) is issued without the waits spec/permissions.md §3 and spec/sync-ids.md §6 put on it (every entry it can open opened at the sources it reaches; no valid `keys.0` part of the actor missing; `flows::sync_ids::due_at`).

## status and API
- Covered by a snapshot at a source (spec/sync-status.md §2): needs the engine's covering snapshots of a commit; a body a source dropped under a snapshot before showing it never counts (an under-claim).
- `caps()`/`set_caps` in the osis API over `caps^.0` (the engine reads `caps^.0`; nothing writes it but a raw write).

## facade
- The complete-pass want of a role found gone (spec/permissions.md §2, which `lost_leaving` waits on).
- Nothing calls `history_complete` (spec/sync-status.md §3) from the API.
- Home stays under it (spec/sync-set.md §1): nothing refuses a write cutting a synced group from D or D from it; a node so cut follows no change of its synced group until paired again (`Engine::pair` then writes it a new one).

- A blob's prefix commitment groups are checked against the commit's delete keys only when its header's linked lists resolve here (`Engine::open_commit`; spec/sync-ids.md §1, spec/crypto.md §7); its expiry is checked always. Until the lists resolve, a reader keeps and serves a blob framed under commitments of its framer's choosing: the thing's delete-key holders cannot delete it (their signatures match no commitment) while its framer can, until its expiry (an open after the lists resolve refuses it, but nothing opens it again for that alone). Fix: hold such a blob unopened (not served) until its lists resolve, then check.
- A stale copy (spec/permissions.md §3: `open_entry` takes none of it, `Opened::NotOpen`) keeps its bytes in the store as an entry that did not open, and is opened again only when S's read secrets move, not when this node gets secrets of the part's actor (`await_reading` names it in `Wakes`, which nothing in osis-sync takes).
- A loss by an `until` alone (`Leaving::timed`, spec/permissions.md §2: dropped once its labels are heard out, or `LOST_HEARD_WAIT_MS` after): the driver's lost-access step (`role_duties`) leaves these, and nothing reads `lost_leaving` for them, so such an actor's secrets are never dropped. Plan: a `Life` key over `lost_leaving().timed` read with the memo clock up to each wait's end and status's heard-out values; the duty drops those heard out or past the wait (`forget_lost(LostScope::Only)`); a reload restarts the modules as any does.

## Wire differs from spec
- Kdf strings in osis-crypto keep the old words where spec/wire.md §8 names new ones (`"osis v1 label id"` for `"osis v1 sync id"`, kdf `"label sync"` and the other `LABEL_*` for `"sync key"`, `"sync claim"`, ...): a node built from the spec cannot open, verify or derive with this one. Rename with their vectors (issues/deprecated-terms.md, label).
- osis-label's link carries a `hosts` list between K's sync ID and the peers that spec/wire.md §10 `Link` does not have.

## Own issues
issues/sync-link-first-contact.md, issues/group-source-hand-off.md, issues/sync-pending-leftovers.md, issues/holder-actor-sync-record.md, issues/sync-sibling-rotation-unopened.md.
