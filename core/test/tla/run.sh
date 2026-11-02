#!/usr/bin/env bash
# Run the TLC model instances. Usage: run.sh small|all [name-filter]
#   small: the CI-sized instance of each model (about a minute in total)
#   all:   every instance (the large ones take up to ~20 min each)
# TLC_KEEP_LOGS=<dir> copies each TLC log there.
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
  "rotation Rotation MC_plant.cfg small pass"
  "rotation Rotation MC_reorder.cfg all pass"
  "rotation Rotation MC_grant_remove.cfg all pass"
  "rotation Rotation MC_safety.cfg small pass"
  "rotation Rotation MC_fork.cfg small pass"
  "rotation Rotation MC_fork_reorder.cfg all pass"
  "rotation Rotation MC_withhold.cfg all pass"
  "rotation Rotation MC_names_own.cfg small fail"       # negative control: own removals only
  "rotation Rotation MC_keyset.cfg small pass"
  "rotation Rotation MC_keyset_nonames.cfg small fail"  # negative control: no keyset names
  "rotation Rotation MC_keyset_forge.cfg small pass"
  "rotation Rotation MC_keyset_forge_rot.cfg all pass"
  "rotation Rotation MC_keyset_forge_nogroup.cfg small fail"  # negative control: no group names
  "rotation Rotation MC_keyset_forge_commit.cfg small fail"   # negative control: commit-named keysets
  "rotation Rotation MC_keyset_forge_write.cfg all pass"      # R18, closed by frozen coverage
  "rotation Rotation MC_c2_box.cfg small fail"         # study C2 under the box-inspection rule
  "rotation Rotation MC_c2.cfg all pass"               # C2 under frozen coverage
  "rotation Rotation MC_c2_boxcovers.cfg small fail"   # negative control: no box counts as covering
  "rotation Rotation MC_c1_box.cfg all fail"           # study C1 under the box rule
  "rotation Rotation MC_c1.cfg all pass"
  "rotation Rotation MC_c1f_box.cfg small fail"        # study C1' under the box rule
  "rotation Rotation MC_c1f.cfg all pass"
  "rotation Rotation MC_c3_box.cfg small fail"         # study C3 under the box rule
  "rotation Rotation MC_c3_current.cfg small fail"     # the study's box-names rule: a grant leaving g out
  "rotation Rotation MC_c3_boxed.cfg small fail"       # ... a grant at an epoch no longer current
  "rotation Rotation MC_c3.cfg all pass"               # names tied to the grant
  "rotation Rotation MC_c3_proj.cfg small pass"        # a grant held as its edge alone: sealed at the named keyset
  "rotation Rotation MC_c3_proj_free.cfg small fail"   # negative control: the boxer's own keyset choice
  "rotation Rotation MC_c3_proj_bad.cfg small pass"    # a second edge naming a keyset nobody holds: bound until a free box arrives
  "rotation Rotation MC_c3_lean.cfg all pass"          # MC_c3 without the fork of g
  "rotation Rotation MC_c3_nonames.cfg small fail"     # negative control: grants carry no names
  "roles Roles MC_core.cfg small pass"
  "roles Roles MC_multi.cfg small pass"
  "roles Roles MC_group.cfg all pass"
  "roles Roles MC_snapA.cfg all pass"
  "roles Roles MC_snapB.cfg all pass"
  "roles Roles MC_until.cfg all pass"
  "roles Roles MC_depth.cfg all pass"
  "roles Roles MC_keepoff.cfg small fail"     # negative control: no kept standing
  "roles Roles MC_sticky.cfg small fail"      # AMBIGUITIES.md M2: drop order
  "roles Roles MC_sticky_snap.cfg small fail" # M2: a snapshot repairs a sticky drop
  "roles Roles MC_forge.cfg small pass"       # AMBIGUITIES.md M1 (fixed)
  "roles Roles MC_samets.cfg small pass"      # AMBIGUITIES.md M3 (fixed)
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
  [ -n "${TLC_KEEP_LOGS:-}" ] && cp "$log" "$TLC_KEEP_LOGS/"
done
exit $failed
