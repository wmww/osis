# keel-own-keys
> Summary: Mishaps met building own keys at creation and aspect-scoped backlinks.

- Two cargo osis tests (`commits::changes_on_as_many_things…`, `commit_work_linear_in_things…`) ran for many minutes once 2,000 things under the account each got own keys: a slow test hides as "running for over 60 seconds" with no hint which rule made it slow. They make their things plain under the account root now.
- A first cut gave own keys at the transaction's end, after a creating commit with content: a later large edit rewrote every chunk (engine `write::large_edit_reuses_chunks_spec_sync_1` caught it). The record-first split (`commit_in`) is the fix; worth knowing for any "after the fact" key change.
- Store bytes per thing from `backend.dump()` jump by tens of KB on a first write of a kind (index pages rewritten); measure over n things after a warm-up, never one.
