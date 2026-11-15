# dial-removed
- A wip-probe commit followed by `git reset --hard HEAD` to undo a mutation also drops edits made after the wip commit (lost the spec and note edits once): commit again before each probe, or undo the probe with `git checkout -p` of the probed file only.
