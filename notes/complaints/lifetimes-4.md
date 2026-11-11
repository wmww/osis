# lifetimes-4
- `Reader::created`/`changed` answered an ended thing's creation (its kept value-less minting), though spec/commits.md §5 says an ended thing reads as absent: found only because a release test checked `created`. Fixed for both; other reads of ended things were not audited.
- `delete` reset `retainers^.0` (it is "content" by `is_content`), which would have made a deleted retained thing standalone and kept for good; `core_types::deletable` now leaves it.
- A node with no runtime still runs the lifetime judgment after every call (`after` -> `SyncEvent::Local`), so a test calling `judge_lifetimes` by hand finds nothing to do: easy to misread as "nothing queued".
- The scratchpad directory must exist before a backgrounded command redirects into it; the first run failed silently with exit 1.
