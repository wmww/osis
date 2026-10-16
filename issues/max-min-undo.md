# Exact undo for max/min
> Summary: Undo of a `set` on a `max`/`min` aspect restores the pre-reset contributions with fresh dots, not the original ones. Owner to decide whether exact undo is needed.
> Tags: crdt, owner-call

Context: spec/crdt.md §5.2, §4.6. Fresh dots mean the restored contributions no longer cancel per dot like the originals.
