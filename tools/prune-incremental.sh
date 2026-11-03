#!/bin/bash
# Frees disk in claimed worktrees between review rounds (wt prunes only at release): removes rustc
# incremental session dirs untouched for HOURS (default 3). The next build recompiles what they held.
set -eu
hours="${1:-3}"
root="$(git rev-parse --show-toplevel)"
find "$root"/.worktrees/*/target "$root"/.worktrees/*/kit/target -mindepth 3 -maxdepth 3 -path '*/incremental/*' -type d -mmin +$((hours * 60)) -exec rm -rf {} + 2>/dev/null || true
df -h "$root" | tail -1
