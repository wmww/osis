# client-port-wait
> Summary: Mishaps while carrying `wait_synced` and the sharing calls through the client port.

- A thing created with no aspect set is ephemeral and in no group closure: `wait_synced(Group(t))` fails `Unsynced([t])` though `groups_of(t).within` lists the group. Cost a debug round in a test; set an aspect first.
- Placing a group in `home` before it is synced makes placing items in it fail `Invalid` ("items reach no synced group"); the CLI e2e works because it runs `group sync` in between.
- `osis wait` takes `--group G`, not a positional; `sync`'s help reads the same. Easy to miss in a test.
