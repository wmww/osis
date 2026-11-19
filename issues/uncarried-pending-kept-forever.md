# A pending commit no entry carries is never let go
> Summary: Sync forgets a pending commit once no store entry names a blob of it; a commit taken with no entry (a fire's carried commit, a stranded report's holder keys: `ingest_valid` with no blobs) names none, so nothing ever forgets it. spec/commits.md §4 Pending storage counts a sealed fire and a stranded report as carriers; the engine tracks neither.
> Priority: normal
> Tags: engine, sync, security

## How it shows
Repro: `cargo test -p osis-engine --test it -- --ignored --exact closure::repro_uncarried_pending_kept_forever` (D on W taken by `ingest_valid`, W's record unknown, W outside the node closure: D pends across pass ends and a restart).

`store::follow::release` returns early for a commit with no blob noted (`Engine::commit_blobs` empty) and is the only caller of `Engine::forget_pending`. So a pending commit, or a waiting part of an applied one, taken from `flows::inbox::take_role_parts` (ticket fires, removal notices) or `sync::stranded` stays while the needs rule keeps its things: forever where it writes on a thing in the node closure (a carried commit naming a fake author or actor whose record never comes), and, with a thing whose record it awaits held for itself (`needed::Root::Awaited`), forever wherever it writes.

## Reach
A removal notice is taken only once its commit names a thing whose roster is held here; a ticket fire's grant only once its ticket is accepted. A removal notice is an external signal, so a stranger whose fire is valid can carry a commit on a held thing that pends for a record it never sends: one pending copy per fire, left after the fire goes. Each fire is bounded by the inbox's budgets; their sum over time is not.

## Fix
Pending storage as written: a commit taken from a fire or a stranded report records that carrier, and goes (`forget_pending`) once its last carrier goes (the fire out of history, the report replaced), as an entry's does. A commit with no carrier at all (a test's bare ingest) goes at once.
