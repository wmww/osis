#!/usr/bin/env python3
"""Tests tools/known_failures_merge.py: the three-way record merge (a removal on either side holds,
additions on both kept, a line whose issue is gone dropped when resolving in a checkout), and as
git's merge driver in a temp repo, where a rebase over a concurrent edit merges with no conflict and
brings back no line the branch removed. Exit 1 on a mismatch."""
import os, subprocess, sys, tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from known_failures_merge import merge  # noqa: E402

fails = 0


def expect(what, got, want):
    global fails
    if got != want:
        fails += 1
        print(f"FAIL {what}:\n  got  {got!r}\n  want {want!r}")


HEAD = "# header\n"
a, b, c, d = (f"crate/t_{x} - issues/{x}.md pat{x}" for x in "abcd")
base = HEAD + f"{a}\n{b}\n{c}\n"
# ours removes b (fixed) and adds d; theirs removes c and edits nothing else
text, report = merge(base, HEAD + f"{a}\n{c}\n{d}\n", HEAD + f"{a}\n{b}\n", lambda _: True)
expect("removals hold on both sides, additions kept", text, HEAD + f"{a}\n{d}\n")
expect("report", sorted(r.split(":")[0] for r in report), ["dropped (removed on ours)", "dropped (removed on theirs)", "kept (added on ours)"])
# both sides add lines next to each other: both kept, no duplicate
text, _ = merge(base, base + f"{d}\n", base + f"{d}\ncrate/t_e - issues/e.md pate\n", lambda _: True)
expect("concurrent additions", text, base + f"{d}\ncrate/t_e - issues/e.md pate\n")
# resolving in a checkout: a line naming a gone issue drops
text, report = merge(base, base, base + f"{d}\n", lambda i: i != "issues/d.md")
expect("gone issue dropped", (text, report[-1].startswith("dropped (issues/d.md is gone)")), (base, True))

# a test's lines changed on both sides are a conflict the driver leaves to a person
import known_failures_merge as kfm  # noqa: E402
expect("both changed", kfm.both_changed(base, HEAD + f"{a} x\n{b}\n{c}\n", HEAD + f"{a} y\n{b}\n{c}\n{d}\n"), ["crate/t_a"])
expect("apart", kfm.both_changed(base, HEAD + f"{b}\n{c}\n", HEAD + f"{a}\n{b}\n{c}\n{d}\n"), [])

# as git's driver: a rebase of a branch removing c over main adding d after it merges cleanly
t = tempfile.mkdtemp(prefix="kfm-test-")


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=t, capture_output=True, text=True, check=check)


git("init", "-q", "-b", "main")
git("config", "user.email", "t@t")
git("config", "user.name", "t")
git("config", "rerere.enabled", "false")
git("config", "merge.known-failures.driver", f"{sys.executable} {HERE}/known_failures_merge.py %O %A %B")
os.makedirs(os.path.join(t, "tools"))
with open(os.path.join(t, ".gitattributes"), "w") as f:
    f.write("tools/known_failures.txt merge=known-failures\n")
kf = os.path.join(t, "tools/known_failures.txt")


def write(s):
    with open(kf, "w") as f:
        f.write(s)


write(base)
os.makedirs(os.path.join(t, "issues"))
for x in "abcd":
    open(os.path.join(t, f"issues/{x}.md"), "w").close()
git("add", "-A")
git("commit", "-qm", "base")
git("checkout", "-qb", "branch")
write(HEAD + f"{a}\n{b}\n")  # the branch fixed c
git("commit", "-qam", "fix c")
git("checkout", "-q", "main")
write(HEAD + f"{a}\n{b}\n{c}\n{d}\n")  # main adds d after c: a text merge conflicts here
git("commit", "-qam", "add d")
git("checkout", "-q", "branch")
r = git("rebase", "main", check=False)
expect("rebase clean", r.returncode, 0)
expect("rebased file", open(kf).read(), HEAD + f"{a}\n{b}\n{d}\n")
# without the driver git conflicts; the tool with no arguments resolves from the index stages
git("config", "--unset", "merge.known-failures.driver")
git("reset", "-q", "--hard", "ORIG_HEAD")
expect("conflicts without the driver", git("rebase", "main", check=False).returncode, 1)
r = subprocess.run([sys.executable, f"{HERE}/known_failures_merge.py"], cwd=t, capture_output=True, text=True)
expect("resolved from the stages", (r.returncode, open(kf).read()), (0, HEAD + f"{a}\n{b}\n{d}\n"))
subprocess.run(["rm", "-rf", t])
print("known_failures_merge_test: ok" if not fails else f"known_failures_merge_test: {fails} failed")
sys.exit(1 if fails else 0)
