# s1-read-review
- A world test meant to catch acts going before agreement passed with the gate removed: the purge's Delete waits on role entries first (the request not yet at the store), so it became owed only after the stream rejoined. A probe printing what is owed and delivered (two eprintlns) found it in one run; checking each new test fails with its rule disabled is what caught it.
- Finding the unattributed store rows took a dozen scope probes in the driver one at a time (30 s each): the rows sat in `Node::next_wake`, outside every module's scope.
