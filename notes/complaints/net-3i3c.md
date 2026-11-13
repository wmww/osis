# net-3i3c
- 3i3c as briefed (merge the records, per-label state on every connection, `HostKey` out, the removal audit) is two jobs: the record merge and a dialer pulling were small; `HostKey` keys the whole presence model (`y/p`, `y/c`, `y/h`, the outbox, pass ends), which 6c replaces, so it was split off (3i3c2).
- The test net's hosts could not dial (`host_feed` panicked on `Action::Dial`): a test of a peer dialing a reader needed `Net::host_dial` first.
- `read_as_host` meant "a dialed, listed connection with L a member"; once a node keeping L unread could dial, it read its dialed reader's stream as a host's and dropped every row of L. A name hid the assumption that hosts never dial.
- Review gate waited 57 min for the heavy lock: another agent's by-hand heavy run (histcut-k3) held it 61 min while two gates queued.
- Rebasing the four branch commits one by one would have hit the same 11 conflicts twice (the `LConn` rename sits in the second commit): squashed first, resolved once.
- A sync-only holder was judged departed by J (any role ever, read role now), so the first test of a Sync holder dialing a reader opened nothing; the test net's hosts cannot be granted roles (no keyset at the grantor), so the dialer had to be a full node with the hub path copied in by hand.
- Showing raw sync keys in a reader's filter looked like the smallest change and passed every node test; only osis `runtime::a_paired_peer_serves_what_it_reads_in_process` (4 runs in 6) showed two readers opening by sync key through the walk. A distinct proof credential fixed it.
