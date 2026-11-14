# pieces-cost
- The store stamps an absent row by its hash bucket (64 per table): a per-piece judgement reading tombstone or delete-seen rows that are absent moves on any removal in its bucket, so cost tests over many keys see noise (a count test asserts `< 2x`, not equality).
- `cargo test -p A pieces:: read::` is a cargo argument error; filters go after `--`.
- A redirect into a scratch dir not yet made fails the whole backgrounded command quietly (`mkdir -p` first; the preamble says so).
