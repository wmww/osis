# prose-issues
- Code comments still cite deleted issues: core/test/tla/run.sh (blocked-walk-stops-at-readers), core/engine/src/apply/tests_addenda.rs (revocation-without-arbiter), core/engine/src/apply/memory.rs cites `scale::eph_decoded_memory` (now `memory::`). Workers deleting an issue should grep code for its name too.
- notes/api.md Writes and notes/whole-commits.md say a creating commit cannot expire (two commits for expiring content); notes/expiry-creation-design.md says a disappearing message is one commit. One of them is stale; not resolved here.
