# delete-levels-2
> Summary: workflow notes from the delete-levels-2 job.

- The brief's part 1 assumed a purge-by setting; purge-by is per delta and its levels are already checked (`Header::validate`). Reading `core/commit/src/validate.rs` before the spec would have shown this sooner.
- No build or footguns met: this was a design pass that stopped at a tradeoff.
