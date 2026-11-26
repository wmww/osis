#!/usr/bin/env python3
"""Merges tools/known_failures.txt as a set of records, three ways (notes/gate.md, Policy checks):
a line either side removed stays removed (its failure was fixed, or its line went stale), a line
either side added is kept, also for a test whose lines both sides changed (said so: read which
pattern and seed hold); resolving a conflict in a checkout (no arguments), a line whose issue
file the merged tree lacks is dropped too (the fix deleted it). Union merge would bring a removed line back beside the other side's change, and a
revived line for a test that still fails passes every check and hides the next failure there.
Prints each line it dropped and each it kept from one side only, so the resolution is read.

  tools/known_failures_merge.py BASE OURS THEIRS   git's merge driver (%O %A %B): the result in OURS
  tools/known_failures_merge.py                     resolve a conflicted tools/known_failures.txt in
                                                    this checkout from git's index stages 1-3

The driver is `.gitattributes` `merge=known-failures` with `merge.known-failures.driver` in the
repo's git config (tools/claim sets it; the worktrees share it). Without it git falls back to its
text merge, which conflicts; then run this with no arguments. Exit 0 merged, 1 a side unreadable."""
import os, subprocess, sys

KNOWN = "tools/known_failures.txt"


def records(text):
    """(header comment lines, record lines in order) of a known-failures text."""
    head, recs = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        (recs if recs or not line.startswith("#") else head).append(line)
    return head, [r for r in recs if not r.startswith("#")]


def merge(base, ours, theirs, issue_exists):
    """(merged text, report lines): ours' header, then ours' records not removed by theirs, then
    theirs' additions; a record whose ISSUE (third field) issue_exists says is gone is dropped."""
    _, b = records(base)
    head, o = records(ours)
    _, t = records(theirs)
    bs, os_, ts = set(b), set(o), set(t)
    out, report = [], []
    for line in o + [x for x in t if x not in os_]:
        if line in out:
            continue
        if line in bs and (line not in os_ or line not in ts):
            report.append(f"dropped (removed on {'ours' if line not in os_ else 'theirs'}): {line}")
            continue
        f = line.split(None, 3)
        if len(f) >= 3 and not issue_exists(f[2]):
            report.append(f"dropped ({f[2]} is gone): {line}")
            continue
        if line not in bs and not (line in os_ and line in ts):
            report.append(f"kept (added on {'ours' if line in os_ else 'theirs'}): {line}")
        out.append(line)
    return "\n".join(head + out) + "\n", report


def both_changed(base, ours, theirs):
    """The NAMEs (first field) whose lines both sides changed: a concurrent edit of one test's
    record, which a person reads after the merge (each side's pattern and seed may be the right one)."""
    _, b = records(base)
    bs = set(b)
    changed = [{x.split()[0] for x in set(side) ^ bs} for side in (records(ours)[1], records(theirs)[1])]
    return sorted(changed[0] & changed[1])


def main(argv):
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip() or os.getcwd()
    exists = lambda issue: os.path.isfile(os.path.join(root, issue))
    if len(argv) == 3:
        try:
            texts = [open(p).read() for p in argv]
        except OSError as e:
            print(f"known_failures_merge: {e}", file=sys.stderr)
            return 1
        # mid-merge the checkout is neither side's tree, so issue files are not judged here
        # (tools/policy.py refuses a line whose issue is gone)
        text, report = merge(*texts, lambda _: True)
        report += [f"both sides changed the lines of {n}: read what was kept" for n in both_changed(*texts)]
        with open(argv[1], "w") as f:
            f.write(text)
    elif not argv:
        stages = []
        for n in (1, 2, 3):
            r = subprocess.run(["git", "show", f":{n}:{KNOWN}"], cwd=root, capture_output=True, text=True)
            stages.append(r.stdout if r.returncode == 0 else "")
        if not stages[1] and not stages[2]:
            print(f"known_failures_merge: {KNOWN} is not conflicted (no index stages 2 and 3)", file=sys.stderr)
            return 1
        text, report = merge(*stages, exists)
        report += [f"both sides changed the lines of {n}: read what was kept" for n in both_changed(*stages)]
        with open(os.path.join(root, KNOWN), "w") as f:
            f.write(text)
        report.append(f"wrote {KNOWN}: read it, then `git add {KNOWN}`")
    else:
        print(__doc__, file=sys.stderr)
        return 1
    for line in report:
        print(f"known_failures_merge: {line}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
