# port-calls
> Summary: footguns met while carrying API calls through the client port.

- Mutation testing by hand: `git checkout <file>` to undo a mutation also drops uncommitted work in that file. Commit (wip) before mutating.
- `internals::port_answers` returns only Replies: a fake connection has no push room, so a node-side Notify cannot be seen there. Wire-level "nothing told" checks count Notifies a thin client received instead (`costs::count("port: notify")`).
- (review) `port_answers` sessions are per node: two differential runs on one node with the same connection/session ids fail the second Auth (code 1), easy to misread as a leak. Give each run its own ids.
- (review) Status rows that depend on live sync sources (`connected`, `not_taking`) have no test with a real second syncing node: two-node sync tests are `#[ignore]`d until the sync facade lands.
