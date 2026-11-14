# Sync: opens
> Summary: osis-sync's `opens` module (core/sync/src/opens/): per-peer records, agreement, filters and Hits, the shared set per connection and the walk; how it follows credentials by change, how records are kept durable and evicted, the seams its tests use, and what is stubbed.

Spec: spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk. Model: core/test/tla/net/NetOpen.tla (each rule it flags is one function here, named in its comment). Overview: notes/sync.md.

## What it owns
- **Records** (`opens/records.rs`, rows in the peer's osis-store record under tags `R` own state: `acked_pos`, this side's filter generations and the positions they reach, the peer filter's shape; `F` the peer's filter per generation, Golomb-Rice coded, a whole one replacing those before it; `M` a member: class, credential, `until`, beacon; `O` how a member that left rejoins). No walk state is durable.
- Per connection: binding, phase, agreement, filter generations in flight, the Hits its filter makes possible, the Offer in flight, reported positions (`Positions`), walk state, and `lost_to` (the pair rule).
- `changed_at` per S: the store's `changed_note` row, keeping the digest of the credentials it was advanced for, so a restart advances it only for a value that moved.

Opens reports each member joining or leaving a connection's shared set as a `Moved` (`Joined` with a `Rejoin`, `Left`, `Until`); the driver hands each to streams, read, status and inbox at once. Opens never calls streams; streams never diffs the shared set. Streams' reported positions come back as `Reported` and fold into `Positions` (O(1) per report; an Applied checks only ended members).

## Work follows change
`NodeHolds::due` follows the sync set per key (`set::SetFollow`) and, per S, the digest of its credentials (`node_creds`: the engine's `read_credentials(s)` for a read S, `Unread::credentials(s)` for one kept unread) as an `Effects` key. A moved value advances `changed_at(S)`, re-judges S's members on the connections holding it, and makes a filter addition and a test due on each connection. Nothing walks every sync ID per connection but a whole filter (first contact) and the Hits index, built at a connection's first Hit and then kept per changed S, so a reconnect the peer Hits nothing on costs nothing per sync ID held (issues/opens-hit-index-cost.md).

## Audiences and ending
- A connection's audience (spec/sync-opens.md §4 Audiences: whether the peer proved a known actor) is judged at its proof and again only when the engine's `known_actors` moves (`Holds::known_moved`, an `Effects` value); a change makes the next generation whole. A Hit on a read secret is judged by the same flag.
- An ended member's `until` (`holds::member_until`): at a node keeping S unread the position of S's head event (`Store::head_at`); at a reader opened by a read secret of epoch e the highest first-logged position in S of an entry of a rotation superseding e (`Engine::rotations_superseding`, entries by `commit_blobs`), else the log's end; a credential with no epoch at a reader (sync key, claim, proof, static entry) ends at the log's end. A store failure answers 0 (served to nothing, closed at once). A Lost's cursor below a reported position is `Store::cursor_at(until)`.

## Credentials as built
- Read S: `roles` is `ReadCredentials::roster`, so a role change moves `changed_at(S)` and a reader granted again opens by J. Shows each current read secret, every static entry of S's roster, and the sync proof of the newest recorded step; tests the read secrets, the static entries of the key actors it acts for (`ReadCredentials::acting`, a link it redeems), and the recorded steps deepest first by sync key, else claim key.
- Kept unread: `Creds::kept_unread` over `Unread::credentials` (its steps' sync keys and proofs shown and tested: the head's, or with no head every sync secret's of the record; the head's deposit key and claim set shown; a Hit on a sync key is answered by that key, anything else by `step`, the head's or the newest secret's). Stranded: an empty `Creds`; S stays in the sync set, so its `changed_at` moves and the peer gets a generation. The scripted tests build their fake from the same function, so a test cannot pass on credentials the product lacks.
- A Deposit item goes into the store charged to the peer's record, else the connection. A Behind is answered from the store's path, trying each key kind in turn (the item names none); a signature that does not verify answers 13 for a sync ID not kept unread, else 14. A Behind answered 13 does nothing more: once the peer keeps S, its own test opens it (it tests its step's sync proof, which a reader shows).
- A static Hit is answered from the path kept (a reader's recorded one, else the store's) with the head's entry box. `take_grant` opens the grant (`Engine::open_grant`: the path verifies from genesis through the newest step recorded here, the box opens for a held key actor, its sync secret derives the head's sync key) and learns it (`Engine::learn_grant`) only once the answer's signature verifies under that key.

## Durability and eviction
A kept record is created in the store at once, before the answer naming it goes and before any module writes rows in it; Resume lists and the listener's lookup read the store (`records_of_actors`). A connection taking a record loads it (O(members, rejoins, filter entries)) unless memory holds it. Every other change marks the record dirty, and `Opens::flush` writes it at the end of the step, after streams wrote the positions it moved: a crash between leaves opens' older word, which streams' rows cover (a member that left is stopped there; a join's cursor is streams' `joining` row). `flush` then evicts past `RECORD_BUDGET` (records in use: held by a connection or listed in a Resume out), each evicted record with its charges in one transaction (`Store::write_records`), so no peer's entries outlive its record, and drops from memory records no connection holds. Every row counts toward the budget, the peer filter's included; in memory a peer filter is a sorted `Vec<u64>` behind an `Arc`, at most 2^22 entries (the format's bound). A store failure inside a step is noted (`fault`) and fails the step at `settle` or `flush`.

The walk: a reader tests a sync ID only on its own changes and re-marks, never at a peer's filter alone; a store that starts keeping S opens it by its own test, and one whose head moves ends the members open by the old key (a Lost, which re-marks). A walk Hit refused (a filter false positive) marks the walk `missed`: the next test skips its walk credentials and asks Behind.

One connection per pair (spec/sync-opens.md §1) is judged before a record is taken (`one_per_pair`: the smaller `pair_order` loses, `lost_to` names the winner); two live connections never share one record's members.

## Seams
The core (`Opens::message`, `tick`, `closed`) runs over `opens::Ctx { holds: &mut dyn Holds, wire: &mut dyn Wire, store, now }`: `Holds` is what the node holds per S (`NodeHolds` over the engine and unread; a test's table), `Wire` the session calls (`Sessions`; a test's pipe). So the rules run against scripted peers (core/sync/tests/it/harness/scripted.rs).

## Reasons
- A peer with no record has its unstamped charges per connection (spec/sync-ids.md §5 Peer budget): dropping and fetching again beats a row keyed by a node key.
- `RESYNC_MS` (30 s): after a refused generation a whole filter follows; streams has its own `RESYNC_MS` for a refused join. They are separate constants of the same value.

## Not built
issues/sync-unbuilt.md (opens): records' named actors judged at the proof alone; static entries claimed in the walk's tests. issues/sync-walk-reopen.md: `verify_steps` and `step_creds` answer nothing.
