# keel-tools-audit
> Summary: Mishaps met while auditing tools/.

- Transcript evidence is noisy: policy_test.py prints the whole planted policy output on any failure, so violation messages in transcripts mostly come from plant runs, not real hits. Count `"command":"...tools/X` invocations instead.
- notes/time-limits.md had about 350 commits in a week, nearly all reviewers appending gate hits that 97% of gates hit (limits.log: 172 of 177 gates over `gate`). The log already had them.
- tools/dead_pub_allow.txt had about 100 commits in a week; 84 of its 131 lines were `test hook`s (items integration tests need `pub`), a false-positive class built into the check.
