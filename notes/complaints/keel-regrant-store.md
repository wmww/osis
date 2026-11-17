# keel-regrant-store
> Summary: Mishaps met on the regranted-store, duplicate-notice-path and Signed-need tasks.

- The issue's repro was no bug: a sync-only grantee gets its secret only by its inbox ticket, so cut off from the granter it holds nothing, regranted or fresh. Checking a fresh grantee in the same world first would have shown that in one run.
- `tools/mutate.py` with several plants builds them as `if .. { NEW } else { OLD }`: an iterator plant (`std::iter::empty()` against a `Map<..>`) does not type-check and fails the whole build; run such plants alone as plain edits.
- A probe `sed` I made in the tree was never reverted, which made a later scripted edit's assertion fail. Make probe edits through `mutate.py`, or revert them right away.
