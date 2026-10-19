# Commit rules that need delta contents are checked nowhere yet
> Summary: osis-commit validates what a header shows; osis-perm judges edge writes. Rules of spec/commits.md §2 and spec/permissions.md §3, §5 that need the decoded deltas of a membership commit are checked by neither; node-core owns them (plans/node-core.md).
> Tags: commit, node, permissions

Unchecked rules (each needs the commit's decoded membership deltas):
- A membership commit changes at most one `/members` edge, except a single-use link redemption (grant plus L's self-removal) and a roster snapshot (spec/commits.md §2).
- The frontier is present iff the commit carries an explicit demotion (spec/wire.md §4 position 13; osis-commit only checks it appears on kind 1).
- A removal or demotion carries the rotation of the target's roles it requires: the `/secrets` and `/keys` deltas (spec/commits.md §2, spec/permissions.md §3).

Owner: node-core, at apply time after verification (`osis_commit::verify_blob`), feeding osis-perm. A violation is bad input for the whole commit.
