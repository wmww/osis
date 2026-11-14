# port-calls
> Summary: footguns met while carrying API calls through the client port.

- Mutation testing by hand: `git checkout <file>` to undo a mutation also drops uncommitted work in that file. Commit (wip) before mutating.
- `internals::port_answers` returns only Replies: a fake connection has no push room, so a node-side Notify cannot be seen there. Wire-level "nothing told" checks count Notifies a thin client received instead (`costs::count("port: notify")`).
