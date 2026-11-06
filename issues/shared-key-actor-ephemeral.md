# May a shared key actor write ephemeral data?
> Summary: spec/commits.md §3 has a key actor used from several nodes (link key, recovery key) write in commit form, and an ephemeral content commit in session form, so such an actor cannot write ephemeral data; `validate.rs` refuses the shape. Decide and say so in the spec.
> Tags: spec, commit

Options:
- Let a shared key actor use session form for content (a random per-start nonce is safe on several nodes, the reason session form replaced node form): the commit-form MUST in §3 then covers only role commits and compaction snapshots. Recommended if anything needs it; check the tie and frontier code treats such sessions like any node's.
- State that a shared key actor writes no ephemeral data (a sentence in §3 and an `Invalid` at the API).
