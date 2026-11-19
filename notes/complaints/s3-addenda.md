# s3-addenda
> Summary: workflow mishaps met on the s3-addenda branch.

- `cmd; echo policy $?; git commit ... && git push` pushed past a policy violation: the `echo` resets the exit, so chain the commit on the policy call itself (`python3 tools/policy.py --baseline && git commit ...`).
- Editing a source file while a chained background `cargo test -p A; cargo test -p B` runs makes the later commands build the half-done edit; I had to stop one mid-build. Set the edit aside (a copy) or wait until the whole chain is done.
- Tests that need a commit pending at a peer: a content commit on a thing minted under a held thing enters the node closure at once (no `Outside` wait); delivering it before its thing's creation (a `Record` wait) works, with `hold_at` once the creation arrives.
