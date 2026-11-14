# net-6c-1
> Summary: workflow snags met building 6c commit 1.

- The plan's "Ready to paste" spec text describes all of 6c at once; commit 1 could paste only its parts (side byte, proof from the seed), so the rest had to be cut out sentence by sentence. A per-commit split of that text would save the next worker the sorting.
- The reflection test needed a reader whose Hit table holds a static entry for a peer that did not prove its key actor; `answer_static_hit`'s node `t` does not (it knows no actor of the dialer before its grant), so a test built on it would likely pass for the wrong reason. Built on `net_judgment::linked` with the account node holding the key actor instead.
