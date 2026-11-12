# chunk-release-one-rule
- The issue's lost-access loss did not reproduce through node-sync: `forget_records` keeps any blob an entry under a kept label names, and every scenario built (hosted, wiped host, peer-only, self-listing) left t2's chunks such an entry or a held lister. The new test fails on main only with that entry check disabled; several build-and-run rounds went to finding that out.
- `git checkout <file>` on a test file with uncommitted work wiped a draft test; a wip commit first would have kept it.
