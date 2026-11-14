# sync-spec-review
> Summary: Workflow snags met while reviewing the Phase 1 sync spec.

- notes/sync-rewrite-inputs.md cites its own lines by number ("For Tess" 31, 32, 88 …; coverage "Lines 9-35"), and the numbers are off by one or more against the file: every edit above shifts them. Cite by quoted text or a short tag instead.
- The sync spec is ~2,400 lines over 12 files with long single-line bullets; a cat of three files overflows the tool output and needs a second read. A per-file reading order in spec/sync.md §4 would help a fresh reviewer.
- spec/wire.md §11.2 defined `item :=` twice (Offer item and Delete item): grep for a grammar name found the wrong one.
