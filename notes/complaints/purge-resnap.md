# purge-resnap
- `net.blocked.insert((c, host))` blocks only c's host link: c still syncs with its group's peers directly, so a "never held" test node held the write anyway and the test passed with the fix disabled. Use `net.set_online(c, false)`.
- `t:reg.0`'s default retention keeps history forever, so a purged write's header stays as a lasting header and a node that never held the body still reads the purge right: another way such a test passes with the fix off. Give the purged write a bounded retention.
- A purge committed by a node that was offline can stamp before a write it names (HLC behind): `net.advance` first, or the request names nothing.
