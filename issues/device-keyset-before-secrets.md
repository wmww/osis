# A device that gets an actor's keyset before its secrets stops syncing its label
> Summary: `compute_labels` skips a labeled thing with no read secret held. A person's second device that holds a `keys.0` keyset part of a K it owns, with no box yet, treats K as an actor it cannot read, so it never opens K's label: never gets the box, and a dedicated `admit own` host device never admits it. Today it stays plain till K's label is synced, as nothing carries K's rotation under another label.
> Tags: node, sync

Met carrying K's rotation under its target's label (spec/permissions.md §4): `own_host_device_localhost` then timed out on `link make`, code 14. Such a device could claim the label by its entry box. Any later carrier of a keyset (a compaction snapshot, a card) would meet this. Also: `inbox_chain` sends each thing's newest `keys.0`, which may be an inbox write with no keyset, though it says the recipient judges by it; nothing fails on it yet.
