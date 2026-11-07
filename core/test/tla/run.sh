#!/usr/bin/env bash
# Run the TLC model instances. Usage: run.sh small|all [name-filter]
#   small: the CI-sized instances, each under ~2 min at one worker (about 6 min in total)
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
  "sync MC kept.cfg small pass"
  "sync MC kept_after.cfg small pass"
  "sync MC none.cfg all pass"
  "sync MC none_live.cfg small pass"
  "sync MC purge_reach.cfg all pass"
  "sync MC purge.cfg all pass"
  "rotation Rotation MC_live.cfg small pass"
  "rotation Rotation MC_drop.cfg all pass"
  "rotation Rotation MC_drop_refresh.cfg all fail"  # issue reseal-triggers (closed: a manual re-share, notes/label-access.md) residue 2
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
  "sides MC kill_touch.cfg small pass"        # notes/disputes-plan.md step 6
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
  "rotation Lockout L_list.cfg all pass"              # lockout recovery by listing (notes/lockout-recovery.md)
  "rotation Lockout L_list_honest.cfg all pass"      # ... the rotator boxed h too (a rotation missing a)
  "rotation Lockout L_list_missed.cfg all pass"      # ... h's rotation leaves a out: the removal goes alone, h rotates
  "rotation Lockout L_two.cfg all pass"              # two rogues: the first removal goes alone, the second recovers
  "rotation Lockout L_two_write.cfg all pass"        # ... with a write (NoLeak, Repairable)
  "rotation Lockout L_two_own.cfg small fail"        # negative control: lacked epochs only the removed rogue's
  "rotation Lockout L_probe_refused.cfg small fail"  # probe: the refusal is reached
  "rotation Lockout L_fork.cfg small fail"           # negative control: a fork from a's own epochs
  "rotation Lockout L_none.cfg small fail"           # negative control: no recovery
  "rotation Depth0MC D0_nc.cfg small pass"            # rule 4, no key cycles (notes/crypto.md (Holder actors at depth 0))
  "rotation Depth0MC D0_nc_rev.cfg small pass"
  "rotation Depth0MC D0_nc2.cfg all pass"
  "rotation Depth0MC D0_nc3.cfg small pass"
  "rotation Depth0MC D0_nc_below.cfg all pass"
  "rotation Depth0MC D0_via_late.cfg all pass"        # rotate only holding every current secret (spec/crypto.md §4 Boxes)
  "rotation Depth0MC D0_via_lax.cfg small fail"       # negative control: a merge over a fork it cannot read
  "rotation Depth0MC D0_stall.cfg all pass"           # a box carrying a secret is encrypted under its recipient's key (spec/crypto.md §4 Encrypting under); unfinished at 100k states
  "rotation Depth0MC D0_stall_write.cfg all pass"     # ... and the removed reader opens nothing written knowing it
  "rotation Depth0MC D0_stall_strict.cfg all fail"    # negative control: two rotators lacking each other's fork stall (13 min at one worker)
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
  "rotation Depth0MC D0_fork_old.cfg all fail"        # two knowing forks of a holder never merged (cycle harness seed 1838)
  "rotation Depth0MC D0_fork_old_safety.cfg all fail" # ... and a rotation over forked anchors drops them (leak)
  "rotation Depth0MC D0_fork_out.cfg small fail"      # merging forks, leaving the holder out: the same leak
  "rotation Depth0MC D0_fork_live.cfg all pass"       # the fork's merger merges; Seal waits while anchors fork
  "rotation Depth0MC D0_fork_wait.cfg all pass"
  "rotation Depth0MC D0_fork_rm.cfg all pass"         # a removal goes alone while Seal waits
  "rotation Depth0MC D0_above.cfg all pass"           # ... and things above the actor leave it out (Blocked)
  "rotation Depth0MC D0_above_live.cfg all pass"
  "rotation Depth0MC D0_readers.cfg small fail"       # blocked walk stops at actors the node may not rotate (issues/blocked-walk-stops-at-readers.md)
  "rotation Depth0MC D0_readers_out.cfg small pass"   # ... descending through every held epoch
  "rotation Depth0MC D0_readers_wait.cfg small pass"  # ... waiting instead of leaving out
  "rotation Depth0MC D0_readers_g2.cfg small fail"    # ... a second admin of G re-seals A where it was left out
  "rotation Depth0MC D0_readers_g2_mark.cfg all pass" # ... the rotation records the keyset it left A out at
  "rotation Depth0MC D0_above_g2.cfg small fail"      # alone-above has the same re-seal hole
  "rotation Depth0MC D0_fa_flip.cfg small pass"         # first admin removed: a keyless grant turns keyed, re-sealed (spec/crypto.md §4 Key access)
  "rotation Depth0MC D0_fa_derive.cfg small fail"       # a derived write after the own-secrets switch stays unread
  "rotation Depth0MC D0_fa_dmerge.cfg small pass"       # ... the writer merges it (DMerge)
  "rotation Depth0MC D0_fa_dmerge_rm.cfg small fail"    # ... unless it learns its removal first (stated limit)
  "rotation Depth0MC D0_fa_both.cfg all pass"
  "rotation Finalize F_named_seed3.cfg small pass"       # a finalize names the writes it ends (notes/permissions.md (Keys))
  "rotation Finalize F_named_bogus.cfg small pass"
  "rotation Finalize F_named_renew.cfg all pass"
  "rotation Finalize F_old_seed3.cfg small fail"         # name met by the commit alone: seed 3 leaks
  "rotation Finalize F_branch_seed3_erase.cfg small fail" # lowering writes applied: erase finalize leaks
  "rotation Finalize F_branch_renew.cfg all fail"         # ... and a renewal locks out
  "rotation Finalize F_issue_seed3.cfg small fail"        # rotate instead of re-seal: history leaks
  "rotation Finalize F_partial_all.cfg all fail"          # known writes apply alone: name covers too much
  "rotation Finalize F_partial_bogus.cfg small fail"      # ... and an unheld reset locks out
  "rotation Cover C_leaver_mark.cfg small fail"           # negative control: any live entry covers (the leaver lists its self-removal)
  "rotation Cover C_drop_any.cfg small fail"              # negative control: a departure attributed to a later audit drop
  "rotation Cover C_drop.cfg small pass"                  # attribution to the newest lowering (notes/crypto.md (Frozen coverage))
  "rotation Cover C_leaver.cfg all pass"                  # the author rule against every forgery of the leaver
  "roles Roles MC_core.cfg small pass"
  "roles Roles MC_multi.cfg small pass"
  "roles Roles MC_group.cfg all pass"
  "roles Roles MC_until.cfg all pass"
  "roles Roles MC_depth.cfg all pass"
  "roles Roles MC_keepoff.cfg small fail"     # negative control: no kept standing
  "roles Roles MC_sticky.cfg small fail"      # AMBIGUITIES.md M2: drop order
  "roles Roles MC_forge.cfg small pass"       # AMBIGUITIES.md M1 (fixed)
  "roles Roles MC_first.cfg small pass"
  "roles Roles MC_samets.cfg all pass"        # two commits of one node at one ts
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
