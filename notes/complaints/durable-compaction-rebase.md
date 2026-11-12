# durable-compaction-rebase
> Summary: footguns met rebasing durable-compaction and chunk-blind over eph-paging and 3h1.

- Main's 3h1 removed the label reconcile (`sync_label`, `reconcile_after`) that durable-compaction's fallen-snapshot rule called; the spec (sync.md §7, §9) still says "reconciles the label (§6)" while the code relists by stream. Porting the rule meant reading what replaced it, not resolving text.
- Main's trigger change (weigh a part with its pages) looked like it should apply to durable too; doing so made every large-value write compact (a durable body's chunk list holds live value chunks the snapshot keeps), failing six chunk tests. The pages/value-chunk distinction is invisible in a chunk list.
- New tests merged to main while the branch was out (peer budgets) write one register repeatedly and break under automatic compaction: each such merge needs the same "keep its history" fix.
