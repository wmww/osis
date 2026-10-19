#!/usr/bin/env bash
# Run the TLC model instances. Usage: run.sh small|all [name-filter]
#   small: the CI-sized instance of each model (about a minute in total)
#   all:   every instance (the large ones take up to ~20 min each)
# Downloads tla2tools.jar into ~/.cache/tla/ if missing. Exits non-zero if
# any instance fails, except those listed as expected failures below, which
# must fail (an unexpected pass is an error too: update the docs).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
jar=${TLA_JAR:-$HOME/.cache/tla/tla2tools.jar}
workers=${TLC_WORKERS:-1}

# dir module cfg size expect
instances=(
  "sync MC deposit.cfg small pass"
  "sync MC mostabs.cfg small pass"
  "sync MC purge_reach.cfg all pass"
  "sync MC timed.cfg all pass"
  "sync MC timed_live.cfg all pass"
  "sync MC purge.cfg all pass"
  "rotation Rotation MC_live.cfg small pass"
  "rotation Rotation MC_drop.cfg all pass"
  "rotation Rotation MC_drop_refresh.cfg all fail"  # issues/reseal-triggers.md residue 2
  "rotation Rotation MC_grant.cfg small pass"
  "rotation Rotation MC_reorder.cfg all pass"
  "rotation Rotation MC_grant_remove.cfg all pass"
  "rotation Rotation MC_safety.cfg small pass"
  "rotation Rotation MC_fork.cfg small pass"
  "rotation Rotation MC_fork_reorder.cfg all pass"
)

mode=${1:-}
filter=${2:-}
case "$mode" in small|all) ;; *) echo "usage: $0 small|all [filter]" >&2; exit 2;; esac

if [ ! -f "$jar" ]; then
  mkdir -p "$(dirname "$jar")"
  curl -sSL -o "$jar.tmp" https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
  mv "$jar.tmp" "$jar"
fi

meta=$(mktemp -d)
trap 'rm -rf "$meta"' EXIT
failed=0
for line in "${instances[@]}"; do
  read -r dir mod cfg size expect <<<"$line"
  [ "$mode" = small ] && [ "$size" != small ] && continue
  [ -n "$filter" ] && [[ "$dir/$cfg" != *"$filter"* ]] && continue
  start=$(date +%s)
  log="$meta/$dir-$cfg.log"
  (cd "$here/$dir" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "$workers" \
     -metadir "$meta/states" -config "$cfg" "$mod") >"$log" 2>&1 || true
  secs=$(( $(date +%s) - start ))
  states=$(grep -oE '[0-9,]+ distinct states found' "$log" | tail -n 1 | cut -d' ' -f1 || true)
  if grep -q 'No error has been found' "$log"; then got=pass
  elif grep -qE 'is violated|were violated' "$log"; then got=fail
  else got=error; fi
  if [ "$got" = "$expect" ]; then verdict=ok; else verdict=FAILED; failed=1; fi
  printf '%-8s %-22s %-5s (expected %-4s) %10s states %5ss  %s\n' \
    "$dir" "$cfg" "$got" "$expect" "${states:-?}" "$secs" "$verdict"
  if [ "$verdict" = FAILED ]; then grep -E 'Error|violated' "$log" | head -n 5 | sed 's/^/    /'; fi
done
exit $failed
