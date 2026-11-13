#!/bin/bash
# Frees disk in claimed worktrees between review rounds (wt prunes only at release): removes rustc
# incremental session dirs untouched for HOURS (default 3). The next build recompiles what they held.
# Works from the main checkout or any worktree: the repo root is the parent of the shared git dir.
set -eu
hours="${1:-3}"
root="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
mapfile -t dirs < <(find "$root"/.worktrees/*/target -mindepth 3 -maxdepth 3 -path '*/incremental/*' \
  -type d -mmin +$((hours * 60)) 2>/dev/null)
if ((${#dirs[@]})); then
  freed="$(du -sch "${dirs[@]}" | tail -1 | cut -f1)"
  rm -rf "${dirs[@]}"
  echo "freed $freed in ${#dirs[@]} incremental dirs untouched for ${hours}h under $root/.worktrees"
else
  echo "nothing to free: no incremental dirs untouched for ${hours}h under $root/.worktrees"
fi
df -h "$root" | tail -1
