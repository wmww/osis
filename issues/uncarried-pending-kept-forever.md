# A pending commit no entry carries is never let go
> Summary: Sync forgets a pending commit once no store entry names a blob of it; a commit taken with no entry (a fire's carried commit, a stranded report's holder keys: `ingest_valid` with no blobs) names none, so nothing ever forgets it. spec/commits.md §4 Pending storage counts a sealed fire and a stranded report as carriers, and a commit taken from none counts as never received at once; the engine tracks neither. A content part waiting outside the node closure on such a commit roots its thing (`Root::Awaited`) for good.
> Priority: normal
> Tags: engine, sync, security

## How it shows
Repro: `cargo test -p osis-engine --test it -- --ignored --exact closure::repro_uncarried_pending_kept_forever` (D on W taken by `ingest_valid`, W's record unknown, W outside the node closure: D pends across pass ends and a restart).

`store::follow::release` returns early for a commit with no blob noted (`Engine::commit_blobs` empty) and is the only caller of `Engine::forget_pending`. So a pending commit, or a waiting part of an applied one, taken from `flows::inbox::take_role_parts` (ticket fires, removal notices) or `sync::stranded` stays while the needs rule keeps its things: forever where it writes on a thing in the node closure (a carried commit naming a fake author or actor whose record never comes), and, with a thing whose record it awaits, or whose entry into the node closure it awaits without its minting commit held, rooted for itself (`needed::Root::Awaited`), forever wherever it writes.

## Reach
A removal notice is taken only once its commit names a thing whose roster is held here; a ticket fire's grant only once its ticket is accepted. A removal notice is an external signal, so a stranger whose fire is valid can carry a commit on a held thing that pends for a record it never sends: one pending copy per fire, left after the fire goes. Each fire is bounded by the inbox's budgets; their sum over time is not.

## Fix
Pending storage as written, one mechanism for every carrier:
- **Carriers persisted per pending commit**: an entry (sync ID, blob: what sync tracks today), a sealed fire (its inbox entry, gone when the fire leaves history), a stranded report (its sync ID, replaced by the next report). Stored with the pending copy, rebuilt nowhere else; `forget_pending` runs when the last goes, as an entry's does today.
- **No carrier, never kept**: a commit taken from none (a test's bare `ingest`, `ingest_valid`) counts as never received at the end of its transaction if it pends or a part of it waits.
- What a waiting part is carried by follows the same set; `needed::uncarried` (minting commit held: judged in no synced unit) stays the only other way a waiting part goes.

State table the fix must keep (a part on thing T, by what is held of T; each row the same in every arrival order):

| T | certificate part (record, role-class, secrets; key actor's card) | content part | header of a commit missing a part on T |
| --- | --- | --- | --- |
| held whole (closure, leaving, retained copy) | applies | applies | kept, part fetched |
| outside, minting commit held | applies; kept while needed | waits; never received at the pass end | kept while a part on a thing in the closure is missing, else goes with T |
| outside, minting commit not held (record from a record blob or fire, or none) | applies once the record is known | waits while carried, rooting T | kept while carried |

Tests owed with it: each carrier kind letting go (fire out of history, report replaced, entry shredded), a no-carrier ingest gone at the transaction's end, the repro above passing, and the table's rows through the order harness.
