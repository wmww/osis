#!/usr/bin/env bash
# Run one TLA+ module's TLC instances. Usage: run.sh <module> [cfg...]
#   <module>: sync, sides, rotation, joint, jointrule, depth0, lockout, cut, finalize, cover, tail, authority, account, netstream, netshared, netblind, netopen, nethold, netdestroy, netkeep
#   no cfg: the module's instances listed below (each module under 3 min at
#   one worker); with cfg names: those instances instead (the larger ones
#   in the module's README, by hand), judged only if listed below.
# The branch that edits a model (or its spec sections) runs its module.
# TLC_WORKERS (default 1); TLC_KEEP_LOGS=<dir> copies each TLC log there.
# Downloads tla2tools.jar into ~/.cache/tla/ if missing. Exits non-zero on a
# TLC error or a result other than the expected one (a listed fail is a
# negative control or an open finding: it must fail).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
jar=${TLA_JAR:-$HOME/.cache/tla/tla2tools.jar}
workers=${TLC_WORKERS:-1}

# module dir tla cfg expect
instances=(
  "sync sync MC deposit.cfg pass"
  "sync sync MC kept.cfg pass"
  "sync sync MC kept_after.cfg pass"
  "sync sync MC none_live.cfg pass"
  "sides sides MC kill_touch.cfg pass"           # notes/disputes-plan.md step 6
  "sides sides MC purge_touch.cfg pass"
  "sides sides MC place_touch.cfg pass"
  "sides sides MC branch_kill.cfg pass"          # host branching, rule lifted per branch
  "sides sides MC branch_bridge.cfg pass"        # ... members carry clean bodies across
  "sides sides MC concede.cfg pass"              # a concession ends the fork
  "sides sides MC tidy_need.cfg pass"            # the need rule: one-side superseded writes go
  "sides sides MC kill_none.cfg fail"            # negative control: no gate, loss and loop
  "rotation rotation Rotation MC_grant.cfg pass" # liveness
  "rotation rotation Rotation MC_plant.cfg pass"
  "rotation rotation Rotation MC_safety.cfg pass"
  "rotation rotation Rotation MC_reorder.cfg pass"
  "rotation rotation Rotation MC_fork.cfg pass"
  "rotation rotation Rotation MC_c2_boxcovers.cfg fail" # negative control: a box-less holder covered
  "joint rotation JointMC J_gone.cfg pass"        # a forked holder actor sealed jointly: A's rotation needs nobody of M (spec/crypto.md §4 Seal)
  "joint rotation JointMC J_stay.cfg pass"        # ... every member no fork removes reads A, with one admin of M staying
  "joint rotation JointMC J_wait_gone.cfg fail"   # negative control: waiting for M's merge stalls A's rotation
  "joint rotation JointMC J_newest.cfg fail"      # negative control: M sealed at its newest keyset leaks
  "jointrule rotation JointRule JR_every.cfg pass"    # a joint box blocked by departures only when every keyset misses one
  "jointrule rotation JointRule JR_party.cfg fail"    # negative control: per departed party leaks
  "jointrule rotation JointRule JR_any.cfg fail"      # negative control: blocked by any keyset leaves M out needlessly
  "depth0 rotation Depth0MC D0_nc.cfg pass"      # rule 4, no key cycles (notes/crypto.md (Holder actors at depth 0))
  "depth0 rotation Depth0MC D0_nc3.cfg pass"
  "depth0 rotation Depth0MC D0_fa_flip.cfg pass" # first admin removed: a keyless grant turns keyed
  "depth0 rotation Depth0MC D0_fa_dmerge.cfg pass" # liveness: a derived write is merged
  "depth0 rotation Depth0MC D0_rm_possess0.cfg pass" # possession
  "depth0 rotation Depth0MC D0_readers.cfg fail" # negative control: Walk "rotator" leaks above (README)
  "depth0 rotation Depth0MC D0_half.cfg fail"    # negative control: Authority judged on secrets.0 alone leaks
  "depth0 rotation Depth0MC D0_half_keys_ns.cfg pass" # Authority judged from the keyset's proofs (spec/crypto.md §4)
  "depth0 rotation Depth0MC D0_gone_live.cfg pass" # a node's own departure blocks nothing (spec/crypto.md §4)
  "depth0 rotation Depth0MC D0_gone_role.cfg fail" # negative control: judging a holder actor only while in it re-seals into a leave-out
  "depth0 rotation Depth0MC D0_order.cfg pass"   # a keyset whose secret the node lacks is judged by order (spec/crypto.md §4)
  "depth0 rotation Depth0MC D0_destroyed_live.cfg pass" # a destroyed holder actor's frozen holders boxed in its place (spec/crypto.md §4 Destroyed)
  "depth0 rotation Depth0MC D0_destroyed_off.cfg fail"  # negative control: a destroyed actor boxed as any other strands a newcomer
  "depth0 rotation Depth0MC D0_destroyed_cycle.cfg pass" # a frozen holder keyed only through keyed grants (spec/crypto.md §4 Destroyed)
  "depth0 rotation Depth0MC D0_destroyed_cycle_old.cfg fail" # negative control: a frozen holder always keyed closes the key cycle
  "lockout rotation Lockout L_rogue.cfg pass"    # notes/crypto.md (Lockouts)
  "lockout rotation Lockout L_none.cfg fail"     # negative control: no re-key
  "cut rotation Cut X_names.cfg pass"            # history cuts (issues/history-less-grant.md)
  "cut rotation Cut X_race.cfg pass"
  "cut rotation Cut X_cut_old.cfg fail"          # negative control: no floor
  "cut rotation Cut X_cut_oldadd.cfg fail"       # negative control: the History add without the carry rule
  "cut rotation Cut X_cut_nocarry.cfg fail"      # negative control: carry rule off
  "cut rotation Cut X_cut_nofloor.cfg fail"      # negative control: boxing rule off
  "cut rotation Cut X_names_noreplace.cfg fail"  # negative control: no re-placing of role commits
  "cut rotation Cut X_host.cfg pass"             # a hostile history-less writer rotating with any floor or listing
  "cut rotation Cut X_gone.cfg pass"
  "cut rotation Cut X_host_nomaker.cfg fail"     # negative control: the carry rule blind to e's maker
  "cut rotation Cut X_acc_nogfloor.cfg fail"     # negative control: a history-less admin grants history
  "cut rotation Cut X_cap_nocap.cfg fail"        # negative control: a floor above n
  "cut rotation Cut X_host2_nolist.cfg fail"     # negative control: floors read as written
  "cut rotation Cut X_readd_fresh.cfg pass"      # a re-added member's new node opens what it read before its removal
  "cut rotation Cut X_readd_fresh_noreadd.cfg fail" # negative control: the re-add boxes m only at the cut
  "cut rotation Cut X_two_strict.cfg fail"       # accepted: two history-less adds at once each read content beside the other's
  "finalize rotation Finalize F_named_bogus.cfg pass" # notes/permissions.md (Keys)
  "finalize rotation Finalize F_old_seed3.cfg fail"   # negative control: a name met by its commit alone
  "cover rotation Cover C_drop.cfg pass"         # notes/crypto.md (The pin)
  "cover rotation Cover C_dup.cfg pass"          # concurrent removals each pin
  "tail rotation Tail T_raise2.cfg pass"         # the pin over every small edge history (raises; T_raise, T_raise4 by hand)
  "tail rotation Tail T_fin2.cfg pass"           # ... (finalizes; T_fin by hand)
  "tail rotation Tail T_raise_old.cfg fail"      # negative control: the per-event attribution rule
  "tail rotation Tail T_fin_any.cfg fail"        # negative control: a named write pins without taking M down
  "tail rotation Tail T_chain.cfg pass"          # ... (an invalidator voided by another: validity not monotone)
  "tail rotation Tail T_chain_commit.cfg fail"   # negative control: an applied name met by holding its commit
  "tail rotation Tail T_fin_takes.cfg fail"      # negative control: an applied name met only where it takes (Live)
  "cover rotation Cover C_regrant_reader.cfg fail" # the stated limit: a reader's write does not count
  "cover rotation Cover C_leaver_keyless.cfg fail" # negative control: a leaver holding through a keyless grant counted (Holds)
  "authority rotation AuthorityMC A_order_nobase.cfg pass" # keysets read as of the commit's key (spec/crypto.md §4, Possession)
  "authority rotation AuthorityMC A_order_3.cfg pass"
  "authority rotation AuthorityMC A_held_nobase.cfg fail" # negative control: keysets read as held now give two fixpoints
  "account rotation Account Acc_descent.cfg pass"   # an account epoch covers a removal by descent (spec/crypto.md §4 Encrypting under)
  "account rotation Account Acc_order.cfg fail"     # negative control: judged by order, an ignorant fork ordered after the removal covers it
  "account rotation Account Acc_nomet.cfg fail"     # negative control: a seed taken under a D epoch whose names are unmet extends a line past a removal its maker does not hold
  "account rotation Account Acc_unread.cfg pass"    # a box to the writer's account behind a keyset it cannot open is judged (spec/crypto.md §4 Encrypting under)
  "account rotation Account Acc_unread_stop.cfg fail" # negative control: the walk stops at that keyset
  "account rotation Account Acc_namer_anyline.cfg fail" # negative control: a removal named off the open line owes no rotation
  "netstream net MCStream S_loss.cfg pass"
  "netstream net MCStream S_restore.cfg pass"
  "netstream net MCStream S_copies.cfg pass"
  "netstream net MCStream S_join.cfg pass"
  "netstream net MCStream S_oneway.cfg pass"
  "netstream net MCStream S_live.cfg pass"
  "netstream net MCStream SN_inc.cfg fail"
  "netstream net MCStream SN_copies.cfg fail"
  "netstream net MCStream SN_infer_lit.cfg fail"
  "netstream net MCStream SN_infer_knew.cfg fail"
  "netstream net MCStream SN_joindur.cfg fail"
  "netstream net MCStream SN_joinans.cfg fail"
  "netstream net MCStream SN_lostolder.cfg fail"
  "netstream net MCStream SN_cursor.cfg fail"
  "netstream net MCStream SN_gate.cfg fail"
  "netstream net MCStream SN_bothpull.cfg fail"
  "netstream net MCStream SN_sreconcile.cfg fail"
  "netstream net MCStream SN_rearm.cfg fail"
  "netstream net MCStream SN_history.cfg fail"
  "netstream net MCStream SN_listdels.cfg fail"
  "netshared net MCShared T_cred.cfg pass"
  "netshared net MCShared T_gain.cfg pass"
  "netshared net MCShared T_remove.cfg pass"
  "netshared net MCShared T_recloss.cfg pass"
  "netshared net MCShared T_copies.cfg pass"
  "netshared net MCShared T_hostile.cfg pass"
  "netshared net MCShared T_until.cfg pass"
  "netshared net MCShared T_follow.cfg pass"
  "netshared net MCShared T_followdrop.cfg pass"
  "netshared net MCShared T_followrem.cfg pass"
  "netshared net MCShared T_live.cfg pass"
  "netshared net MCShared TN_pending.cfg fail"
  "netshared net MCShared TN_ack.cfg fail"
  "netshared net MCShared TN_untilack.cfg fail"
  "netshared net MCShared TN_arrival.cfg fail"
  "netshared net MCShared TN_tag.cfg fail"
  "netshared net MCShared TN_until.cfg fail"
  "netshared net MCShared TN_genbase.cfg fail"
  "netshared net MCShared TN_byrole.cfg fail"
  "netshared net MCShared TN_reconcile.cfg fail"
  "netshared net MCShared TN_retest.cfg fail"
  "netshared net MCShared TN_decline.cfg fail"
  "netshared net MCShared TN_report.cfg fail"
  "netshared net MCShared TN_cursorrep.cfg fail"
  "netshared net MCShared TN_offergate.cfg fail"
  "netshared net MCShared TN_reptested.cfg fail"
  "netblind net MCBlind B_all.cfg pass"
  "netblind net MCBlind B_live.cfg pass"
  "netblind net MCBlind BN_upack.cfg fail"
  "netblind net MCBlind BN_whole.cfg fail"
  "netblind net MCBlind BN_cover.cfg fail"
  "netblind net MCBlind BN_known.cfg fail"
  "netopen net MCOpen O_rk.cfg pass"               # issues/sync-rewrite.md, the open rule: a reader and a store
  "netopen net MCOpen O_kk.cfg pass"               # ... two stores
  "netopen net MCOpen O_rx.cfg pass"               # ... a reader and a link holder
  "netopen net MCOpen O_pub.cfg pass"              # ... Adv holds only public values
  "netopen net MCOpen ON_side.cfg fail"            # negative control: no side byte, a signature is reflected
  "netopen net MCOpen ON_answer.cfg fail"          # negative control: a Hit on a public value opens
  "netopen net MCOpen ON_old.cfg fail"             # negative control: an older step's sync key answers
  "netopen net MCOpen ON_proofpub.cfg fail"        # negative control: the proof from the public sync key
  "netopen net MCOpen ON_proofold.cfg fail"        # negative control: an older step's proof counts
  "netopen net MCOpen ON_linkold.cfg fail"         # negative control: a removed static entry counts
  "netopen net MCOpen ON_jnow.cfg fail"            # negative control: J from the roster the node started with
  "netopen net MCOpen ON_endj.cfg fail"            # negative control: an open by J outlives a removal
  "netopen net MCOpen ON_endsync.cfg fail"         # negative control: an open by sync key outlives the head's event
  "netopen net MCOpen ON_endproof.cfg fail"        # negative control: an open by proof outlives the rotation
  "netopen net MCOpen ON_endlink.cfg fail"         # negative control: an open by static entry outlives its removal
  "netopen net MCOpen ON_departed.cfg fail"        # finding: without the departed clause a removal does not end opens at once
  "netopen net MCOpen ON_dialer.cfg fail"          # negative control: the dialer trusts the key it dialed
  "netopen net MCOpen ON_nolisten.cfg fail"        # negative control (Live): listeners never sign
  "nethold net MCHold H_quiet.cfg pass"            # hold/log/delete per sync ID (net/README.md)
  "nethold net MCHold H_head.cfg pass"
  "nethold net MCHold H_meet.cfg pass"
  "nethold net MCHold H_full1.cfg pass"            # a full store: a carrier it lacks counts as held
  "nethold net MCHold H_full2.cfg pass"
  "nethold net MCHold H_expire.cfg pass"           # tombstones expire
  "nethold net MCHold H_host.cfg pass"             # a hostile writer deleting at K
  "nethold net MCHold H_live.cfg pass"             # liveness: settles
  "nethold net MCHold HN_stand.cfg fail"           # negative control: no stand, log-liar loop (Bounded)
  "nethold net MCHold HN_standfall.cfg fail"       # negative control: stand blind to a fall, the cover fell and b stays deleted
  "nethold net MCHold HN_fallany.cfg fail"         # negative control: only a fall of a held part ends the stand
  "nethold net MCHold HN_fresh.cfg fail"           # negative control: logged again under the tombstoned blob ID
  "nethold net MCHold HN_known.cfg fail"           # negative control: carrier from own store, not K's stream (Carried)
  "nethold net MCHold HN_readers.cfg fail"         # negative control: a Delete between readers (NoLoss)
  "nethold net MCHold HN_rolefirst.cfg fail"       # negative control: logged again before K takes x
  "nethold net MCHold HN_delview.cfg fail"         # negative control: a delete ignores a role commit K showed
  "nethold net MCHold HN_full.cfg fail"            # negative control: a full store waits for a carrier it refuses
  "nethold net MCHold HN_invalid.cfg fail"         # negative control: a snapshot dropped as invalid blocks establishment
  "nethold net MCHold HN_ownlog.cfg fail"          # negative control: the author keeps a covered body in its log (Settles)
  "nethold net MCHold HL_capjunk.cfg fail"         # stated limit: an invalid body holds a full store's room
  "nethold net MCHold HN_standhead.cfg pass"       # rule not needed here: stand ground without the head
  "nethold net MCHold HN_snap.cfg pass"            # rule not needed here: no unheld-snapshot clause
  "netdestroy net MCDestroy D_present.cfg pass"    # destruction and emptying (net/README.md)
  "netdestroy net MCDestroy D_away.cfg pass"
  "netdestroy net MCDestroy D_live.cfg pass"
  "netdestroy net MCDestroy D_live2.cfg pass"
  "netdestroy net MCDestroy DN_req.cfg fail"       # negative control: emptying deletes the destroying request
  "netdestroy net MCDestroy DN_told.cfg fail"      # negative control: emptying before told
  "netdestroy net MCDestroy DN_stand.cfg fail"     # negative control: no stand, the released-team storm
  "netdestroy net MCDestroy DN_forget.cfg fail"    # negative control: forget while an entry is known
  "netkeep net MCKeep K_all.cfg pass"              # a node keeping S unread follows its own grant
  "netkeep net MCKeep KN_drop.cfg fail"            # negative control: drop on a head move with no box
  "netkeep net MCKeep KN_open.cfg fail"            # negative control: open by any held sync secret
  "netkeep net MCKeep KN_sig.cfg fail"             # negative control: a removal notice's signature unchecked, a forged one drops the store
  "netkeep net MCKeep KF_late.cfg fail"            # finding: a notice signed before the removing step, arriving after it, never verifies
  "netkeep net MCKeep KF_regrant.cfg fail"         # finding: the removal's old notice drops a re-granted K
  "netkeep net MCKeep K_held.cfg pass"             # the spec's rule: fixes KF_late and KF_regrant
)

module=${1:-}
shift || true
dir="" tla=""
for line in "${instances[@]}"; do
  read -r m d t _ <<<"$line"
  [ "$m" = "$module" ] && dir=$d tla=$t
done
if [ -z "$dir" ]; then
  echo "usage: $0 sync|sides|rotation|joint|jointrule|depth0|lockout|cut|finalize|cover|tail|authority|account|netstream|netshared|netblind|netopen|nethold|netdestroy|netkeep [cfg...]" >&2
  exit 2
fi

runs=()
if [ $# -eq 0 ]; then
  for line in "${instances[@]}"; do
    read -r m _ _ cfg expect <<<"$line"
    [ "$m" = "$module" ] && runs+=("$cfg $expect")
  done
else
  for cfg in "$@"; do
    cfg=${cfg%.cfg}.cfg
    expect=any
    for line in "${instances[@]}"; do
      read -r m _ _ c e <<<"$line"
      [ "$m" = "$module" ] && [ "$c" = "$cfg" ] && expect=$e
    done
    runs+=("$cfg $expect")
  done
fi

if [ ! -f "$jar" ]; then
  mkdir -p "$(dirname "$jar")"
  curl -sSL -o "$jar.tmp" https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
  mv "$jar.tmp" "$jar"
fi

# TLC states on disk under the worktree's target/, never tmpfs /tmp (RAM is the constraint)
mkdir -p "$here/../../../target"
meta=$(mktemp -d "$here/../../../target/tlc.XXXXXX")
trap 'rm -rf "$meta"' EXIT
failed=0
total=$(date +%s)
for r in "${runs[@]}"; do
  read -r cfg expect <<<"$r"
  start=$(date +%s)
  log="$meta/$cfg.log"
  (cd "$here/$dir" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "$workers" \
     -metadir "$meta/states" -config "$cfg" "$tla") >"$log" 2>&1 || true
  rm -rf "$meta/states"
  secs=$(( $(date +%s) - start ))
  states=$(grep -oE '[0-9,]+ distinct states found' "$log" | tail -n 1 | cut -d' ' -f1 || true)
  if grep -q 'No error has been found' "$log"; then got=pass
  elif grep -qE 'is violated|were violated' "$log"; then got=fail
  else got=error; fi
  if [ "$got" = error ] || { [ "$expect" != any ] && [ "$got" != "$expect" ]; }; then
    verdict=FAILED; failed=1
  else verdict=ok; fi
  printf '%-24s %-5s (expected %-4s) %10s states %5ss  %s\n' \
    "$cfg" "$got" "$expect" "${states:-?}" "$secs" "$verdict"
  if [ "$verdict" = FAILED ]; then grep -E 'Error|violated' "$log" | head -n 5 | sed 's/^/    /'; fi
  if [ -n "${TLC_KEEP_LOGS:-}" ]; then mkdir -p "$TLC_KEEP_LOGS" && cp "$log" "$TLC_KEEP_LOGS/$dir-$cfg.log"; fi
done
echo "$module: $(( $(date +%s) - total ))s at $workers worker(s)"
exit $failed
