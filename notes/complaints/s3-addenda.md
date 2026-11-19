# s3-addenda
> Summary: workflow mishaps met on the s3-addenda branch.

- `cmd; echo policy $?; git commit ... && git push` pushed past a policy violation: the `echo` resets the exit, so chain the commit on the policy call itself (`python3 tools/policy.py --baseline && git commit ...`).
