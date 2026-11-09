#!/usr/bin/env bash
# Run one TLA+ module's TLC instances. Usage: run.sh <module> [cfg...]
#   <module>: sync, sides, rotation, depth0, lockout, finalize, cover, authority
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
  "depth0 rotation Depth0MC D0_nc.cfg pass"      # rule 4, no key cycles (notes/crypto.md (Holder actors at depth 0))
  "depth0 rotation Depth0MC D0_nc3.cfg pass"
  "depth0 rotation Depth0MC D0_fa_flip.cfg pass" # first admin removed: a keyless grant turns keyed
  "depth0 rotation Depth0MC D0_fa_dmerge.cfg pass" # liveness: a derived write is merged
  "depth0 rotation Depth0MC D0_rm_possess0.cfg pass" # possession
  "depth0 rotation Depth0MC D0_readers.cfg fail" # issues/blocked-walk-stops-at-readers.md
  "depth0 rotation Depth0MC D0_half.cfg fail"    # negative control: Authority judged on secrets.0 alone leaks
  "depth0 rotation Depth0MC D0_half_keys_ns.cfg pass" # Authority judged from the keyset's proofs (spec/crypto.md §4)
  "lockout rotation Lockout L_rogue.cfg pass"    # notes/crypto.md (Lockouts)
  "lockout rotation Lockout L_none.cfg fail"     # negative control: no recovery
  "finalize rotation Finalize F_named_bogus.cfg pass" # notes/permissions.md (Keys)
  "finalize rotation Finalize F_old_seed3.cfg fail"   # negative control: a name met by its commit alone
  "cover rotation Cover C_drop.cfg pass"         # notes/crypto.md (Frozen coverage)
  "cover rotation Cover C_drop_any.cfg fail"     # negative control: attribution to any audit drop
  "authority rotation AuthorityMC A_order_nobase.cfg pass" # keysets read as of the commit's key (spec/crypto.md §4, Possession)
  "authority rotation AuthorityMC A_order_3.cfg pass"
  "authority rotation AuthorityMC A_held_nobase.cfg fail" # negative control: keysets read as held now give two fixpoints
)

module=${1:-}
shift || true
dir="" tla=""
for line in "${instances[@]}"; do
  read -r m d t _ <<<"$line"
  [ "$m" = "$module" ] && dir=$d tla=$t
done
if [ -z "$dir" ]; then
  echo "usage: $0 sync|sides|rotation|depth0|lockout|finalize|cover|authority [cfg...]" >&2
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

meta=$(mktemp -d)
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
  if [ -n "${TLC_KEEP_LOGS:-}" ]; then cp "$log" "$TLC_KEEP_LOGS/$dir-$cfg.log"; fi
done
echo "$module: $(( $(date +%s) - total ))s at $workers worker(s)"
exit $failed
