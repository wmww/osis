# keel-hang-guard
- The sync World's ROUND_CAP was checked only after `Node::handle` returned, so a settle loop that never ended hung inside the step and the cap never fired; the guard belongs inside the loop.
- A StaticSchema that did not parse silently became an empty schema: engine `retention::tests::invalid_snapshot_is_live_by_dot_spec_commits_5` had passed for a long time over a source with fields written `0 a` instead of `a 0`.
