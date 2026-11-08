# undo-floor review

- Gate took 767 s warm (notes say about 4 min); sim-sweep sat at 254 of 255 for over two minutes.
- Testing a header-less node (a snapshot held without the deltas it compacted) needs `LocalPeer::packages` + `deliver` with a filter; no helper names that case.
