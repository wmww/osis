# growth-study
- `tools/heavy --short` stops `roles-model -- 0 forget-entries` at about 120 CPU-s even at a quarter slice (the attack family runs whole every time); the full run waited for the heavy lock behind other agents' long shrink runs (over 15 minutes queued).
- notes/growth.md row Demotion frontiers said "compacted or not", which read as "every commit ever"; the code (`receipt.rs`) lists only commits not forgotten. The issue had been written from the row, not the code.
