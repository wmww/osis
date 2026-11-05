#!/usr/bin/env bash
# Run every scenario of MC.tla under every mode, one TLC run per property.
# Usage: matrix.sh [scenario-filter] [mode-filter]. Prints one line per
# (scenario, mode): each property pass/FAIL and the largest state count.
# Writes .cfg files and TLC state into a temp dir; JOBS parallel runs (4).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
jar=${TLA_JAR:-$HOME/.cache/tla/tla2tools.jar}
jobs=${JOBS:-4}
work=$(mktemp -d -p "${TMPDIR:-/tmp}")
trap 'rm -rf "$work"' EXIT

# scenario prefix side host aspect rolec
scen=(
  "K K K_SideY {\"b0\"} OneAspect {}"
  "Z Z K_SideX {\"b0\"} OneAspect {}"
  "F F K_SideY {} OneAspect {}"
  "C C K_SideX {\"b0\"} OneAspect {}"
  "P P K_SideY {\"b1\"} P_Aspect {}"
  "Q Q K_SideY {\"t\",\"q\"} OneAspect {\"q\"}"
  "Q0 Q K_SideY {\"t\"} OneAspect {}"
)
# mode gate reup fork coverown bridge
modes=(
  "none none FALSE FALSE FALSE FALSE"
  "a-direct direct FALSE FALSE FALSE FALSE"
  "a-neutral neutral FALSE FALSE FALSE FALSE"
  "a-touch touch FALSE FALSE FALSE FALSE"
  "a-exact exact FALSE FALSE FALSE FALSE"
  "a-aspect aspect FALSE FALSE FALSE FALSE"
  "b none TRUE FALSE FALSE FALSE"
  "c none FALSE TRUE FALSE FALSE"
  "c+a-touch touch FALSE TRUE FALSE FALSE"
  "c+a-touch+bridge touch FALSE TRUE FALSE TRUE"
  "d+a-touch touch FALSE FALSE TRUE FALSE"
)
props="NoLoss Quiesce Served Alike PurgePrompt"

for s in "${scen[@]}"; do
  read -r S pre side hostset aspect rolec <<<"$s"
  [ -n "${1:-}" ] && [[ "$S" != $1 ]] && continue
  for m in "${modes[@]}"; do
    read -r M gate reup fork cov bridge <<<"$m"
    [ -n "${2:-}" ] && [[ "$M" != $2 ]] && continue
    for p in $props; do
      if [ "$p" = NoLoss ]; then chk="INVARIANTS TypeOK NoLoss"; else chk="INVARIANT TypeOK
PROPERTY $p"; fi
      cat >"$work/$S-$M-$p.cfg" <<EOF
CONSTANTS
  Nodes = {"x", "y", "m"}
  Parties = {"x", "y"}
  InitSide <- $side
  Switches = 2
  Bodies <- ${pre}_Bodies
  Valid <- ${pre}_Valid
  Seed <- ${pre}_Seed
  Aspect <- $aspect
  Reasons <- ${pre}_Reasons
  InitHeld <- ${pre}_Held
  InitHost = $hostset
  RoleC = $rolec
  Gate = "$gate"
  ReupOnce = $reup
  Fork = $fork
  CoverOwn = $cov
  Bridge = $bridge
SPECIFICATION Spec
$chk
CHECK_DEADLOCK FALSE
EOF
      echo "$S $M $p $aspect"
    done
  done
done >"$work/list"

run() {
  S=$1 M=$2 p=$3 aspect=$4
  d="$work/$S-$M-$p"
  mkdir -p "$d"
  cp "$here/Sides.tla" "$d/"
  cp "$here/MC.tla" "$d/MC.tla"
  cp "$work/$S-$M-$p.cfg" "$d/MC.cfg"
  (cd "$d" && java -Xmx400m -Djava.io.tmpdir="$d" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 1 \
     -metadir "$d/states" -config MC.cfg MC) >"$d/log" 2>&1
  st=$(grep -oE '[0-9,]+ distinct states found' "$d/log" | tail -n1 | cut -d' ' -f1)
  if grep -q 'No error has been found' "$d/log"; then r=pass
  elif grep -qE 'is violated|were violated|Temporal properties were violated' "$d/log"; then r=FAIL
  else r=ERROR; fi
  echo "$S $M $p $r ${st:-?}"
  if [ "$r" != pass ] && [ -n "${TRACE_DIR:-}" ]; then cp "$d/log" "$TRACE_DIR/$S-$M-$p.log"; fi
}
export -f run
export work here jar
xargs -P "$jobs" -L 1 bash -c 'run "$@"' _ <"$work/list" | sort
