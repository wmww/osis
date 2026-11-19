# s1-flat
- The idle tests take 15 s alone on a loaded box: the 20-thing world's build is the first sync of 18 things to three nodes (brief 3's cost), already shared by every idle test through the fixture cache. Nothing cheaper without first-sync batching.
- The streams history test's `held` chained every opened blob into every sync ID, so it could not take a second sync ID until the test table kept the sync ID per open; a history with ephemeral writes found a pre-existing gap (issues/caught-up-ephemeral-push.md).
- A `sed` with `a.s` meant as "a's" matched and replaced a whole comment line: edit with exact-string tools.
