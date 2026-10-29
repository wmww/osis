# snapshot-duty
> Summary: Net-harness footgun met writing node-sync tests.

- `Net::blocked.insert((n, sv))` keeps node n running and its commits still reach other nodes (a "gone" writer still wrote carriers the other node then held): to remove a node for good use `net.take(n)`.
