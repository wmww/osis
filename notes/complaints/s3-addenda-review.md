# s3-addenda-review
> Summary: workflow mishaps met reviewing the s3-addenda branch.

- Mutation probes built once with env-var toggles (`std::env::var("PROBE_X")`) in the code, one build for eight disabled rules, each test run with its variable: far cheaper than a build per probe. Revert with `git checkout <file>` from a wip commit.
- A debug run of one engine lib test took 2+ minutes at a box load near 30: the 120 s Bash timeout moved it to the background mid-pipe; start any engine build in the background.
