# order-settled
- `OSIS_ORDER_DUMP`'s reads-as-they-change list prints only keys that change to a value: a read going absent (a thing leaving the node closure) never shows, so the dump read as if the node still had the value at the end.
- The dump's index differences list commits, not held secrets: a difference in role secrets (a lost access waiting) shows only as content "absent". `why_kept` and `why_role` of the thing at the node and at the keep-everything node found it in one run.
- A settled shrink is ~9 min for 7 real steps: the 800-step settling tail is replayed in every candidate.
