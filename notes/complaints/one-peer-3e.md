# one-peer-3e
- The node log marked "this start drew" with a memory-overlay row, which `Transaction::suspend` refuses, so the log could not run on the host store's suspended transactions at all; found only by the first test. A store feature built on the overlay should say it needs an unsuspended transaction, or not use it (moved to the pager meta).
- The node log's slot put shredded, so logging turned every upload batch into a shredding commit; only the host's write-count test (`file::host_batch_writes_do_not_grow_with_entries`) caught it, node sync's tests count no shredding commits.
