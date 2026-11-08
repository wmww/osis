# own-serving
- An `on_diagnostic` probe on both nodes got none of the sync engine's refusal lines while a label stayed `Refused` for 40 s (cause not looked into); finding why took `sync_engine(|x| x.label_status())` and `host_config()` dumps by hand.
- The chat flake reproduced only with 12 copies in parallel (about 1 in 40); one at a time it passed 80 of 80.
