# Sync: inbox
> Summary: osis-sync's `inbox` module (core/sync/src/inbox/): deliveries owed, Deposit offers, held entries (inbox blobs taken, deposits promoted, clearing), Register at sources keeping S unread, serving Register/Delete/Stranded/Suspect, and first contact by link; how each follows change, what is durable, the reasons behind its rules, and what is not built.

Spec: spec/sync-inbox.md, spec/sync-ids.md §6 Steps and Register, spec/wire.md §9-§10. Principle and parts: the module doc of core/sync/src/inbox/mod.rs (and each part's). Design reasons for deposits and the inbox: notes/inbox.md. Overview: notes/sync.md.

## Parts
- `deliveries`: inbox blobs owed. The engine's `deliveries` at a start, then `delivery_feed`; each judged by `delivery_taken` (the engine's commit sign: a commit by the recipient on a named thing, stamped after the delivery's and opened under a current read epoch, `labeling::opened::opened_epochs`) or an open of a sync ID the blob names (`delivery_names`) on a connection where the recipient is proven, or, once logged stamped, by this node reading the inbox it logged it under (`took_own`; a deposited one would leave its Deposit item moot: it took it itself; a redeemer's join to its own account, a link's grant to K); seen taken it ends (`Engine::delivered`). Logged stamped by a writer of the inbox, else deposited and offered; sealed again at the blob's expiry (a timer per delivery) or once the inbox moved, never by walking what was sent. Signing keys from `Engine::signers(s, actor)`.
- `offers`: Deposit items, one unanswered per connection; refused for now (4, 5, 12) backed off from `BACKOFF_MIN_MS` (2 s) doubling to `BACKOFF_MAX_MS` (10 min); one taken ends the others' back-off at that peer and S; 14 parked until the deposit key moves or the receiver's next filter. Who may take an offer: offers.rs module doc.
- `held`: every entry through the store's entry feed, each judged by one `Effects` key: inbox blobs taken (and stamped in place by a writer of the inbox), deposits promoted (`Engine::promotable`), own deposits offered to store sources, clearing past `DEPOSITS_WAITING`/`DEPOSITS_WAITING_BYTES`. A deposit's commit from `blob_commit`, else opened once (`open_entry`); one stamped copy per delta by `commit_blobs`/`blob_parts`.
- `register`: the recorded steps (read issues a step once the rotations it registers are logged, notes/sync-read.md) after a store source's step (`Net::head`, the head its stream last named; a Hit names none), each once its stream showed the step's role commits (`Engine::step_needs`, a blob of each present at the source). With no head named and nothing registered there, the genesis step goes at once: a source holding no step takes it before the PullReply that follows, so it holds a head before any entry arrives; one holding a step refuses it (9) and its head event moves the plan on.
- `serve`: Register and Delete (taken by the store's rules), Stranded and Suspect (answered Ok).
- `links`: first contact by link, redeemer's side (links.rs module doc): kept durably until the join is held at a source; meanwhile followed in the engine (`Engine::follow_link`: L held and K's sync ID in the sync set from the link text, only while K is unknown here or no other thing owns that sync ID, `labeling::actors::followable`); the join is written once `Engine::redeemable` (K listed alive on the target's roster, L on K's, and K's keyset held: K's sync ID brings L's grant before the keyset, which is wrapped under the epoch it supersedes and fetched last); forgotten once the join is held or the link ended (`Engine::link_ended`).

`dial_hints` (granting nodes of inbox blobs held, sharer nodes of links being redeemed) are the driver's dial candidates; `may_deposit(conn)` keeps a dialed connection open while a deposit to it may land.

## Taking inbox blobs
- `held` calls `take_inbox` inside an `Effects` settle. A take that writes what it read would be due again at once, every round of every step; `take_inbox` writes nothing when taking again changes nothing (tests/it/keep.rs `taking_an_inbox_blob_again_moves_nothing_spec_sync_inbox_2`).
- A take records every read of its ingest, so a blob whose commit applied is taken once: `held` keeps it in `taken` and, while the commit is held (`holds_commit`), judges it from that alone.
- A recipient below read on every thing named gets a boxes payload (`deliveries::boxes_blob`, spec/wire.md §9): its boxes signed by the commit's author (`author_signer`: the account's open epoch, the node's or a key actor's key). `take_boxes` refuses one whose signature fails under a key held here, takes it whole by a connected author or an accept, else only the boxes of things a synced closure lists (the rest stay an invite request), and writes only sync records; taking again answers the same (Applied while a sync box opens), so a writer of the inbox stamps it in place by the usual act.
- An entry whose prefix no inbox blob has is told from its bytes before any key is read (`Prefix::inbox_shaped`): an inbox is its actor's home sync ID, so it holds the actor's commits too, which no inbox key opens.

## Durable
Store rows `I/d/` (per delivery the blob sent and the open seen, so a restart does not seal again) and `I/r/` (links being redeemed, shredded: they hold the seed). Everything else is followed again from the engine and the store at a start.

## Seams
It reads the facade and the store directly (`Here`: engine, status at a settle, store, time, rng) and the network through `inbox::Net` (sessions, opens, streams; `Links` the product's). Each rule's decision is a plain-value function the tests drive (`held::act_of`, `adds_delta`, `to_clear`, `register::plan`); `Offers` takes its deposit keys as a function and runs over a test `Net` and a real store.

## Reasons
- Promotion checks the author's write right at the writer (spec/sync-inbox.md §4): honest readers deposit others' content, so the depositor's right says nothing.
- A reader refuses every Register (spec/sync-ids.md §6): its path comes from `sync.0` alone.
- An accept is written under home alone (spec/sync-set.md §4) so no other holder learns which accounts sync the thing; it is a subgroup, never an item, since an item's subgroups are outside the closure.
- An offer goes only to a peer that may hold the inbox or S: a deposit tells its taker that this connection's node sends to that inbox.

- A sign of taking counts only where the recipient could not show it without the delivery's grant: an open or a commit under a read epoch current here. A later `ts` proves nothing (the HLC follows wall time), and a member removed and granted again still holds its old epoch, so a write it made before taking the grant would end the delivery with the recipient unable to reach the grant any other way (it cannot open the thing's sync ID).

## Not built
issues/sync-unbuilt.md (inbox): a promotion's chain (`log_chain`: not built); acting on Stranded and Suspect (spec/permissions.md §4); clearing at sources keeping S unread (needs streams' `known` to carry each entry's deposited flag and blob size); a decline stamping in place; opens' members are not stamped, so a source's step moving reaches Register only through its next join. issues/sync-link-first-contact.md: K's commits do not apply at a redeemer.
