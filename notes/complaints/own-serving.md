# own-serving
- An `on_diagnostic` probe on both nodes got none of the sync engine's refusal lines while a label stayed `Refused` for 40 s (cause not looked into); finding why took `sync_engine(|x| x.label_status())` and `host_config()` dumps by hand.
- The chat flake reproduced only with 12 copies in parallel (about 1 in 40); one at a time it passed 80 of 80.
- Review: an edit-then-test of one osis test under load 40 took 5 min (rebuild of osis's `it`); `sharing::failed_redemption_*` runs 9-18 s alone in debug, well over the tier-1 few-seconds target.
