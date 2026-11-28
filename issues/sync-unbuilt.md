# Parts of the rebuilt sync not built yet
> Summary: osis-sync's and its engine facade's stubs and missing rules, ranked by risk (security, data loss, convergence, cost, API), each with the spec rule it leaves unmet and what it costs now; larger gaps have their own issues (end).
> Priority: normal
> Tags: sync

The module notes (notes/sync-*.md) point here. Untested built parts: issues/sync-tests-owed.md.

## Data loss
- **A reader's copy under a superseded stamp** (spec/sync-judgement.md §3 Giving a body, notes/sync-inbox.md) is not deposited once the source's head moved: `Live::deposit` ran only while the reader saw the old head (relay under stamp); nothing deposits after the head event. Seen in a World: a writer writes an ephemeral value, rotates write and goes off while the reader is partitioned; the node keeping S unread restarts and loses it.

## Convergence
- **Stale copies** (spec/permissions.md §3: `open_entry` takes none, `Opened::NotOpen`) are opened again only when S's read secrets move, not when this node gets secrets of the part's actor (`Engine::take_wakes` names such waits; nothing in osis-sync takes them).
- **Freed links** (spec/sync-compaction.md §1): a judgment waiting on a node blob not held (`Engine::freed_wants`) is not fetched; no start judgment of every freed row is built (`judge_freed` is the tests'), so a start judges no waiting row; freed deletes do not wait on Role entries first (spec/sync-judgement.md §3); a row is judged once, so a later body reusing the blob neither stops deletes nor un-frees it here (the reuser's repair restores it).
- `SrcView::role_unheld` is always false: deletes toward a source do not wait for a role commit it lacks (spec/sync-judgement.md §3 Role entries first).
- **Pieces** (Retag, spec/sync-judgement.md §1): a thing leaving a sync unit leaves its pieces under the old sync ID; a non-writer's pieces reach a store source only as deposits, never relayed under the writer's stamp.
- **A source that drops S and keeps it again** (shred, listed again) stays at the step its stream last named for a registrar resuming a stored position: its log forgot S's events, and spec/sync-streams.md §3 names no event for a head gone, so it takes nothing until a registrar with no stored position registers the genesis. A listing from the start naming no head could clear it.
- **Two stamps on one entry**: a reader shown an entry it holds under another stamp that also verifies under its head keeps its own (spec/sync-ids.md §6 Role entries: the lower, as bytes), so two writers stamping under either domain need not settle on one.
- **Wraps**: a peer's entry counting as lacking for its wrap (Duplicates, spec/sync-ids.md §6 Wraps).
- **Ephemeral refused for the memory cap** (`Ingested::TooLarge`, spec/sync-compaction.md §2 Caps) comes again only with its next listing, not once S's held bytes drop: streams must keep the refusal per S with the usage then, as `room` does.
- **Fill order again** (spec/sync-streams.md §4 Fill order, 4): a body queued as not opening keeps its place when a read secret of S arrives; it should park under S's read secrets and be ranked again, as the store's parked entries are.
- **Inbox**: clearing at sources keeping S unread needs streams' `known` to carry each entry's deposited flag and blob size.
- **Role commits given as deposits** (spec/sync-judgement.md §3 Giving a body: a store moved past the step parent a role commit is pinned under) are never promoted (the writer holds the same blob stamped under that parent, spec/sync-inbox.md §4: one stamped copy per delta) and sit in S's deposit budget for good, one per rotation a store skipped. Clearing as specified (§4: every deposit it can do nothing with) would delete them, and the writer, judging them must-hold, gives them again. Before clearing at stores is built: a role entry must leave the budget some other way (a stamp under the store's head beside the pinned one, or role deposits outside the budget yet bounded).
- **A store on a step whose write key and deposit seed no node holds** (every writer of that step gone or from-now, the sync role rotated since) takes no role commit the next step waits on: stamped under a head it cannot verify, and no deposit key of its step to sign a deposit with, so registration there waits forever. A store on a step whose deposit seed was since replaced takes what it lacks only once moved to a step of a seed held (no honest node keeps old seeds).

## Cost
- **Unjudgeable bodies fetched again** (spec/commits.md §4, spec/sync-judgement.md §3 Dropped bodies): needs byte-less entries (`Streams::ask`, notes/sync-read.md); until then an awaiting entry keeps its bytes.
- `Rank::Never` (a keyset without history) has no facade call; when built, an entry ranked never is neither held nor taken, so `pull::concerns` keeps no presence of it (spec/sync-judgement.md §3 `known` must count it).
- **Past-cap registers** keep `past_cap` per sync ID in memory, lost at a restart (spec/sync-ids.md §6 Storage caps: at most once per interval).

## Status and API
- Covered by a snapshot at a source (spec/sync-status.md §2): needs the engine's covering snapshots of a commit; a body a source dropped under a snapshot before showing it never counts (an under-claim).
- Diagnostics: an open refused (sync ID, code) is not reported.
- Nothing calls `history_complete` (spec/sync-status.md §3) from the API; the osis API sets caps by a plain write of `core::CAPS` (the node's entry on its account), with no typed reader beyond it.

## Own issues
issues/sync-link-first-contact.md, issues/sync-pending-leftovers.md; missing tests: issues/sync-tests-owed.md.
