# A store whose sync failed stays Broken until the process restarts

> Summary: After a backend write fails `Unsynced` the store fails `Broken` until it is opened again, and nothing reopens it: node sync's restart waits for a commit that never comes, so the node is stuck until its process restarts (a transient cause, such as a full disk freed again, still needs a restart). That restart is an open in the same boot, which reads the page cache: it may see the failed commit, and redb commits built on its pages (Linux dropped them from write-back) may be lost, or leave the file unreadable, at a later power cut. One fix for both: an open drops the file's clean cached pages first (`posix_fadvise(DONTNEED)` on the redb file, which leaves dirty pages alone and drops the failed ones, marked clean), so it reads what the disk holds; then the owner (engine, hub store) can reopen a `Broken` store itself.
> Priority: normal
> Tags: store, node
