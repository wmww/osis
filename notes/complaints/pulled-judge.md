# pulled-judge
- Passing tests capture stderr: a probe in a test that passes prints nothing without `-- --nocapture`; I misread a base run as "this path never runs" for a while.
- No world handle to a node's read verdicts (`Read::verdict`): diagnosing a verdict in a world test needs an eprintln in `judge::body`.
