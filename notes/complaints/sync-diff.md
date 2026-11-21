# sync-diff
> Summary: Footguns met fixing the sync differential's small-size classes.

- The quiet checks (`unlogged_must_holds`, `unreached_must_holds`) run at the end of every `World::run`, a partitioned one included, not only at the differential's healed end: a panic "at quiet" can come from a mid-script Run cut at its horizon. Read which step's Run panicked before reading the end state.
- `tools/mutate.py` with a statement-plus-expression NEW (`self.moved.insert(..); let Some(..) = ..`) reported "none" failing while a hand edit of the same change failed the test: check a "none" row by hand before trusting it.
- A fake ground's `Stamped` insert of an equal value writes no stamp, so a "read again, unchanged" case needs a second stamped read in the fake (`bodies_read` in read.rs), not a re-insert.
