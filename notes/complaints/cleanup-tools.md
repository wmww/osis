# cleanup-tools
- No tool under tools/ is dead: every script is named in notes/ or by another tool. Most have no tests (policy.py, dead_pub.py, loc.py, heavy, agent-times.py); refactoring them meant diffing old vs new output on injected violations by hand, with the old copy placed in tools/ (they find the repo from their own path).
- ~/.cache/osis/limits.log never rotates (heavy.log rotates at 8 MB); 0.4 MB today, so harmless for now.
