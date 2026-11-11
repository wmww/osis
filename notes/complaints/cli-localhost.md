# cli-localhost complaints
> Summary: by-hand localhost tests went stale for ~160 commits unnoticed; bisect over them costs ~2 min a step and hit two commits that do not build.

- The `localhost::` by-hand tests are run by nobody per branch, so the account switch (`me` the account, `home` its group) left two of them failing on main for about 160 commits. A test whose expectation changes with an API rename would be cheaper to catch if the rename's branch ran it.
- Bisecting needed `git bisect skip` on two account-switch commits that do not build (8e7555b2b, d3cfb63ef), so the culprit could only be narrowed to that three-commit range.
- The serving peer's stderr goes to null in the tests (`serve`), so a failure says only what the client saw; I had to patch the test to see that the failing line was not the one the brief named.
