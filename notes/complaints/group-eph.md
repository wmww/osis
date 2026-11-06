# group-eph
- The rename sweep rewrote AGENTS.md (a symlink to CLAUDE.md) as a regular file: `sed -i`/Python writes replace a symlink with its target's text. Exclude symlinks (`git ls-files -s | grep ^120000`) from scripted sweeps; check `git diff --summary` for `mode change`/typechange lines.
