# grant-copies
- The cards fix (`took_own`) lived only on the unmerged `cards` branch; on sync-rebuild the link-after-lifetime reproducer passed (the sharer kept re-sending), so this branch starts from `cards`.
- The harness had no way to give an account a second node; `World::pair` hands pairing's commits directly, as the product's app carries them.
- A 90-day `advance` with a node down storms the rule cap (one redial per back-off); a test about expiry powers off every node that would dial.
- Edits made while a background `cargo test` was compiling leave its result unclear about which version ran; rerun after.
