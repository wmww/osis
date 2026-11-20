# page-levels-review
> Summary: Workflow notes from the page-levels review.

- Engine tests had no way to shrink wire pages, so a deep link tree was only reachable in osis-crdt; `PageParams::set_test` (thread-local) now reaches every node plug. A world built under it must not go into `LocalPeer::cached` (other tests would read small-page states): build it fresh.
