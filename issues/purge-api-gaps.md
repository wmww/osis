# Purge: listing and refusal errors
> Summary: Two purge API gaps: a purge request names parts retention no longer listed, so they show again as `Purged` (spec/commits.md §7), and a refused purge request reports `needs: Write` to a writer that has it, since the right needed is admin or none.
> Priority: low
> Tags: api, osis, retention, spec

## A purge can list a part that had left the listing
spec/commits.md §7 lists a purged part while its value-less writes are in the state or its keep rule would keep it had the request replaced it (counted from the request's `ts`). A part that had already left the listing (past its keep bound, or dropped by compaction while its writes stay live in a snapshot) shows again as `Purged` after a request names it, e.g. for a day under a setting keeping a day: a purge makes history visible that retention no longer kept.

Seen: keep_day aspect, write a, then b, advance 2 days: listing `[b]`; `Purge::Commit(a)`: listing `[Purged(a), b]`. `Purge::Author` over a member's old writes does it for every one.

Why the request's `ts`: the purged body is gone, so when its writes died (`replaced_at`, judged from the body) cannot be judged any more. A rule that never lists more than unpurged would: count the keep rule from the part's own `ts` (never later than its replacement, so it only shortens), and list no part whose body was dropped before the request. Both stay functions of headers and the state, alike on every node.

## A refused purge reports `needs: Write`
`commit()` refuses a purge request whose rights drop none of the held deltas it names with the engine's `Permission { tid }`, which carries no role, so osis reports `needs: Write` to a writer that has it. The right needed is admin (`admin`, `author_or_admin` sets) or no role at all (`author` on another's write, `nobody`), which `needs: Role` cannot say.

Fix shape: the engine's refusal says which (a role, or none grants it), and osis's error can say "no role" (e.g. its own variant), not a guessed role.
