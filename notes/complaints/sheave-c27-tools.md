# sheave-c27-tools
> Summary: two Small items were worded from a misread: the forging hook existed unnamed in any note, and bare `merge-branch gate` already printed its own usage.

- "A test-only public way to forge a write" already existed (`Engine::commit_hostile`, `commit_forged`, `#[doc(hidden)] pub`, used in about ten engine `tests/it` files), but no note named it, so r18 filed it as missing and this job spent its time confirming that. A note line naming each test hook where it is added (now notes/test-harnesses.md, Forged writes) would have stopped both.
- The merge-branch item said "without a branch"; the failing case was a flag in the branch's place (`gate --plan`). Items quoting the exact command that failed are faster to check.
