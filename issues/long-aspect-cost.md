# One aspect with very many kept writes: what is left
> Summary: Measured `scale::long_aspect` (chat design E). At 10^6 a write takes 2.4 ms before its fsync (measured on tmpfs), a fall of 3*10^5 deltas 11 s, a rise 0.6-11 s; every flip still walks the thing's commits (0.6 s) and the first decodes all headers (+2 GB). A kick over about 2.4*10^5 commits now fails at the author until frontier heads land. Open takes 5 s and 2.6 GB. Numbers in notes/testing.md.
> Tags: node, permissions, performance

Repro: `OSIS_SCALE_N=100000 OSIS_SCALE_DIR=<dir on disk> cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::long_aspect::cost`, `scale::long_aspect::first_sync`. A run of 10^6 took 82 min on tmpfs, about 8 GB of it and 5 GB resident per step.

Fixed here: the join's walk of the aspect (`Indexes::bounded_held`), the quadratic fall (one pass over an unpaged state, `Unmerge` looks dots up in an index), a register's rebuild from every body (`Fragment::settled_above`), deaths judged again without a bound, `demote` succeeding where nobody could apply it.

In order of damage:

1. **A kick over about 2.4*10^5 commits cannot be sent.** The frontier passes `MAX_LIST_BYTES`, so `demote` fails with `Commit(TooLarge("header list"))` and the member stays. Before it succeeded and every receiver refused it. notes/frontier-study.md's heads remove it; frontier F2 still lists keep-forever writes.
2. **Every flip walks the thing's commits**, under the engine lock (`validity::rejudge_all`, its `judge` over `by_thing`): 0.6 s at 10^6 for one flipped write. The first after an open also decodes every header: 3 s more and resident from 2.6 to 4.7 GiB. Heads would let a flip judge what it names.
3. **Open at 10^6**: 5 s CPU, 2.6 GiB resident (2.6 KB per message). Lazy headers: issues/node-core-gaps.md. The first open after a long fill also rewrites the index.
4. **A write while many deltas are invalid** costs 1 us per invalid delta (`Unmerge::probe` walks them per join): 0.30 s at 3*10^5. A received invalid delta runs `Unmerge::of` each, so a node first learning a kicked member's writes is quadratic in them (not measured). Asking per dot which delta owns it would remove both.
5. **Other shapes still read every body on a rise or a fallen winner**: anything but a register, any aspect holding a snapshot, any aspect of a thing holding an import (conservative: a rebuild's stop needs only that no held copy be judged); also an aspect with a relative bound, for its deaths (`replay_all`) and keep-at-most (`recheck_at_most`). A map's rebuild would need an index of which bodies hold what lies under each delta (issues/node-core-gaps.md).
6. **Ingest's CPU per message grows with the aspect during a fill**: 0.75 ms at 10^5, 3.4 at 6*10^5, 5.4 at 10^6, while a write after reopening at 10^6 takes 1.3-4 ms. Unexplained; not a budget break.
7. **Store writes per message grow**: 70 / 115 / 170 KB per batch at 10^4 / 10^5 / 10^6 (about 35 key-tree nodes of 10 KB each); store size stays 1.2-2 KB per message. A disk-wear problem (a 200 B message writes 800 times its size).
8. **Bulk upload**: one writer uploading N offline writes runs 30 engine transactions per message: 4.3 / 6.6 ms per message at 10^4 / 10^5. Only after long offline writing.
9. **Host cap**: `cap_entries` 2^20 per label stops a chat at about 10^6 messages unless the host raises it. Not measured past it.

Purge by author: about 1.4 ms per delta dropped at 10^6, all in one store transaction under the engine lock, so moderating the hostile 10^7-message flood of notes/chat-designs/e.md would stall the node for hours. Chunking would need the request's effect spread over transactions: not built. A history watch delivers one entry read per commit, so a fall of 3*10^5 deltas is that many callbacks on the dispatcher (the engine lock is taken per read).
