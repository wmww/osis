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
  "rotation Rotation MC_c2_box.cfg small fail"         # study C2 under the box-inspection rule
  "rotation Rotation MC_c2.cfg all pass"               # C2 under frozen coverage
  "rotation Rotation MC_c2_boxcovers.cfg small fail"   # negative control: no box counts as covering
  "sides MC kill_touch.cfg small pass"        # notes/owner-removal-plan.md step 6
  "sides MC purge_touch.cfg small pass"
  "sides MC place_touch.cfg small pass"
  "sides MC kill_none.cfg small fail"         # no gate: loss and loop
  "sides MC grantee_direct.cfg small fail"    # gate on the parties' own writes only
  "sides MC fall_neutral.cfg small fail"      # gate by a neutral view
  "sides MC purge_aspect.cfg small fail"      # per-aspect gate: accepted purge stuck
  "sides MC cover_own.cfg small fail"         # one-side covers ungated
  "sides MC reup_once.cfg small fail"         # candidate (b)
  "sides MC fork_split.cfg small fail"        # fork: the race loser's reach
  "sides MC place_order.cfg small fail"       # placement fetched after what it places
  "sides MC branch_kill.cfg small pass"       # host branching, rule lifted per branch
  "sides MC branch_late.cfg small fail"       # branching: a late upload reaches one branch
  "sides MC branch_bridge.cfg small pass"     # ... members carry clean bodies across
  "sides MC concede.cfg small pass"           # a concession ends the fork: no loss, no loop
  "sides MC tidy_touch.cfg small fail"        # per-reason rule: one-side superseded writes stay
  "sides MC tidy_need.cfg small pass"         # need rule: they go
  "rotation Lockout L_list.cfg small pass"            # lockout recovery by listing (notes/lockout-recovery.md)
  "rotation Lockout L_list_honest.cfg all pass"      # ... the rotator boxed h too (an honest rotation missing a)
  "rotation Lockout L_fork.cfg small fail"           # negative control: a fork from a's own epochs
  "rotation Lockout L_none.cfg small fail"           # negative control: today's refusal, no repudiation
  "rotation Depth0MC D0_nc.cfg small pass"            # rule 4, no key cycles (issues/keys-depth0.md)
  "rotation Depth0MC D0_nc_rev.cfg small pass"
  "rotation Depth0MC D0_nc2.cfg all pass"
  "rotation Depth0MC D0_nc3.cfg small pass"
  "rotation Depth0MC D0_nc_below.cfg all pass"
  "rotation Depth0MC D0_nc_2adm.cfg all pass"
  "rotation Depth0MC D0_nc_hide.cfg small fail"       # a grant the sealer does not hold leaks
  "rotation Depth0MC D0_nc_hide_lim.cfg small fail"   # ... past a knowing writer without taint
  "rotation Depth0MC D0_nc_hide_live.cfg all pass"
  "rotation Depth0MC D0_nc_hide_taint_lean.cfg all pass"
  "rotation Depth0MC D0_rm_spec0.cfg small fail"      # removed-member writer rotates (issues/keys-depth0-removed-member-rotates.md)
  "rotation Depth0MC D0_rm_spec.cfg small fail"
  "rotation Depth0MC D0_rm_remover0.cfg small fail"
  "rotation Depth0MC D0_rm_spec0_live.cfg small fail" # ... and stays open to it
  "rotation Depth0MC D0_rm_possess0.cfg small pass"   # the possession rule
  "rotation Depth0MC D0_rm_possess.cfg all pass"
  "rotation Depth0MC D0_box_rule.cfg small fail"      # the dropped Box rule hides a key cycle's box (cycle harness seed 1032)
  "rotation Depth0MC D0_box_ok.cfg all pass"          # ... no Box rule
  "rotation Finalize F_named_seed3.cfg small pass"       # a finalize names the writes it ends (issues/withheld-departures-seeds.md)
  "rotation Finalize F_named_bogus.cfg small pass"
  "rotation Finalize F_named_renew.cfg all pass"
  "rotation Finalize F_old_seed3.cfg small fail"         # name met by the commit alone: seed 3 leaks
  "rotation Finalize F_branch_seed3_erase.cfg small fail" # lowering writes applied: erase finalize leaks
  "rotation Finalize F_branch_renew.cfg all fail"         # ... and a renewal locks out
  "rotation Finalize F_issue_seed3.cfg small fail"        # rotate instead of re-seal: history leaks
  "rotation Finalize F_partial_all.cfg all fail"          # known writes apply alone: name covers too much
  "rotation Finalize F_partial_bogus.cfg small fail"      # ... and an unheld reset locks out
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
