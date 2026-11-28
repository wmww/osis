#!/usr/bin/env python3
"""Replay each `rate:` line of tools/known_failures.txt that HEAD adds over BASE once, and judge it as
the gate will (notes/gate.md, The summary): a line whose pattern can never match its failure's seed
line fails every later gate's replay as NEW-TEXT. tools/land runs it before pushing.

  tools/known_replay.py [BASE]    BASE default origin/main; run from a checkout's root

A line is new when its whole text is not in BASE's list (a changed pattern is new). Each runs at its
REPRO with the gate's own command (test_select.replay_command), unlocked (one seed of one crate), and
is judged by the gate's replay judge (gate_failures.replay), against HEAD's list: it must fail with
every unit matched by a pattern of its NAME, and its own pattern must match one of them (else the
line is dead). Exit 0 when every new line holds or there is none, 1 otherwise, naming why.
"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_failures, test_select


def main():
    if len(sys.argv) > 2 or sys.argv[1:2] in (["-h"], ["--help"]):
        sys.exit(__doc__)
    base = sys.argv[1] if len(sys.argv) == 2 else "origin/main"
    head = [l.strip() for l in open(gate_failures.KNOWN)] if os.path.exists(gate_failures.KNOWN) else []
    shown = subprocess.run(["git", "show", f"{base}:{gate_failures.KNOWN}"], capture_output=True, text=True)
    old = {l.strip() for l in shown.stdout.split("\n")} if shown.returncode == 0 else set()
    new = [l for l in head if l not in old and gate_failures.replays(lines=[l])]
    if not new:
        return 0
    names, errs = gate_failures.known(".")
    if errs:
        print("\n".join(f"known_replay: {e}" for e in errs))
        return 1
    bad = 0
    for line in new:
        for name, repro in gate_failures.replays(lines=[line]):
            pattern = re.compile(line.split(None, 3)[3], re.M)
            cmd = test_select.replay_command(name, repro)
            print(f"known_replay: replaying the new line's REPRO once, as the gate will: {name} {repro}", flush=True)
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            text = f"gate: replay {name} {repro}\n{r.stdout}"
            rows, replayed, stale = [], [], []
            gate_failures.replay(str(r.returncode), text, names, rows, replayed, stale)
            sim = name.startswith("sim-sweep:")
            fails = gate_failures.sim_failures(text) if sim else gate_failures.cargo_failures(text)
            path = gate_failures.test_path(name)
            units = [u for n, us, _ in fails if n == path for u in us]
            why = [t for _, _, t in rows] + [s.strip() for s in stale]
            if not why and not any(pattern.search(u) for u in units):
                why.append(f"{name} at {repro}: fails as listed, but this line's pattern matches none of its units: {units[0].strip().split(chr(10))[0][:200] if units else '?'}")
            if why:
                bad += 1
                tail = "\n".join(r.stdout.rstrip().split("\n")[-30:])
                print(f"{tail}\nknown_replay: refused: " + "\n  ".join(why) + "\n  (the gate matches each failing seed's line, or the whole panic when it names no seed)")
            else:
                print(f"known_replay: {replayed[0].strip()}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
