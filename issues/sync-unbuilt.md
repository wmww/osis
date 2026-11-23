# Parts of the rebuilt sync not built yet
> Summary: osis-sync's and its engine facade's stubs and missing rules, ranked by risk (security, data loss, convergence, cost, API), each with the spec rule it leaves unmet and what it costs now; larger gaps have their own issues (end).
> Priority: normal
> Tags: sync

The module notes (notes/sync-*.md) point here. Untested built parts: issues/sync-tests-owed.md.

## Data loss
- **A reader's copy under a superseded stamp** (spec/sync-judgement.md §3 Reader that is not a writer, notes/sync-inbox.md) is not deposited once the source's head moved: `Live::deposit` ran only while the reader saw the old head (relay under stamp); nothing deposits after the head event. Seen in a World: a writer writes an ephemeral value, rotates write and goes off while the reader is partitioned; the node keeping S unread restarts and loses it.

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
- **A grant's `profile` ticket** to an account the granter may not hold as a contact (spec/sync-inbox.md §5 Grant from outside): the `ticket@~0` fire carries none, so a stranger cannot dial the granter by it.
- **Opens**: static entries claimed in the walk's tests (`Tested::Static` always has no step).

## Cost
- **Unjudgeable bodies fetched again** (spec/commits.md §4, spec/sync-judgement.md §3 Dropped bodies): needs byte-less entries (`Streams::fetch_again`, notes/sync-read.md); until then an awaiting entry keeps its bytes.
- **Sole certificates** (spec/sync-judgement.md §2 may-hold): `BodyFacts::sole_certificate` is always false, so such a certificate is must-hold (logged, relayed, owed). Build it from the author's other blobs under S, or drop the clause if §2's chain-certificate rule covers it.
- **`SETTLE_MS`** (spec/wire.md §2, a MAY wait: spec/permissions.md §3, §4): nothing waits it, so every holder copies another node's demotion or `keys.0` at once (3.3 KB per holder per removal, notes/certificates.md), and every admin makes a dependent thing with holders independent at its pass end (`own_secrets_candidates`), concurrent ones forking.
- `Rank::Never` (a keyset without history) has no facade call; when built, an entry ranked never is neither held nor taken, so `pull::concerns` keeps no presence of it (spec/sync-judgement.md §3 `known` must count it).
- **Past-cap registers** keep `past_cap` per sync ID in memory, lost at a restart (spec/sync-ids.md §6 Storage caps: at most once per interval).

## Status and API
- Covered by a snapshot at a source (spec/sync-status.md §2): needs the engine's covering snapshots of a commit; a body a source dropped under a snapshot before showing it never counts (an under-claim).
- Diagnostics: an open refused (sync ID, code) is not reported.
- Nothing calls `history_complete` (spec/sync-status.md §3) from the API; `caps()`/`set_caps` over `caps^.0` are missing from the osis API (the engine reads `caps^.0`; only a raw write sets it).

## Own issues
issues/sync-link-first-contact.md, issues/sync-pending-leftovers.md; missing tests: issues/sync-tests-owed.md.
