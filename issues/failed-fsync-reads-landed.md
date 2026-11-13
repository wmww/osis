# A write whose fsync failed reads as landed

> Summary: After a failed commit the store recovers in place and reads the outcome from the file (redb reopened, `FileRoot` reloaded). When the failure was the final fsync, the new bytes sit in the page cache, so the commit reads as landed and returns `Ok`; on Linux a failed fsync may already have dropped those dirty pages from the write-back path (the error is reported once), so after a power loss the disk can hold the older state for a commit reported `Ok`. A fresh open in the same boot reads the same page cache, so this is not specific to in-place recovery. Options: treat any failed sync as an unknown outcome (`lost`, Broken until a reopen that cannot help either), or after a failed sync rewrite and sync the landed state before reporting `Ok`.
> Priority: normal
> Tags: store
