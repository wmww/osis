# A reader granted after a writer's removal does not read that writer's last write
> Summary: node 0 grants node 1 write on a thing, node 1 writes (v4) and it syncs, node 0 removes node 1 and grants node 2 read: node 2 reads node 0's earlier value, the reference reads v4. Deterministic minimal reproducer `flows::a_reader_granted_after_a_writers_removal_reads_its_last_write` (ignored); found by the full-size differential.
> Priority: normal
> Tags: sync, tests

- Not investigated. Likely where the removed writer's section may be passed on (spec/crypto.md §5 Passing on: another writer's section is re-encrypted only under the epoch it was written under, and only while that epoch is established at the passer) against what a reader granted after the removal holds (history-less grant floors, spec/permissions.md): either node 2 should hold the old epoch (then sync or the grant fails to give it), or v4 is not readable by it (then the oracle's reference must not count it). Decide which, then fix the side that is wrong; possibly Fathom's (engine judgement).
- Same run (1000 + 1000 histories at `OSIS_FULL=1`, seeds from 188669321349): 6 failures; the others (clean 188669321824; faulty 188669321416, 188669321550, 188669321645, 188669321805) were not shrunk. Replays of a seed are not deterministic (clean 188669321824 failed 2 of 3), so shrink each several times.
