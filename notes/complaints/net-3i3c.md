# net-3i3c
- 3i3c as briefed (merge the records, per-label state on every connection, `HostKey` out, the removal audit) is two jobs: the record merge and a dialer pulling were small; `HostKey` keys the whole presence model (`y/p`, `y/c`, `y/h`, the outbox, pass ends), which 6c replaces, so it was split off (3i3c2).
- The test net's hosts could not dial (`host_feed` panicked on `Action::Dial`): a test of a peer dialing a reader needed `Net::host_dial` first.
- `read_as_host` meant "a dialed, listed connection with L a member"; once a node keeping L unread could dial, it read its dialed reader's stream as a host's and dropped every row of L. A name hid the assumption that hosts never dial.
- Review gate waited 57 min for the heavy lock: another agent's by-hand heavy run (histcut-k3) held it 61 min while two gates queued.
