#!/usr/bin/env python3
"""Tests tools/limits.py's shares (`split`, and a whole over its limit naming its parts over their
share) on a fabricated table and log. Exit 1 on a mismatch."""
import contextlib, io, json, os, shutil, sys, tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import limits

TABLE = """| box | unit (CPU-s) |
|---|---|
| probe | 1 |

| limit | CPU (u) | wall (u) | share of | what |
|---|---|---|---|---|
| whole | 100 | 1000 |  | the whole |
| `a` | 60 | 500 | `whole` | a part |
| b | 30 | 400 | whole | a part |
| lone | 5 | 5 |
"""

fails = 0


def expect(what, got, want):
    global fails
    if got != want:
        fails += 1
        print(f"FAIL {what}:\n  got  {got!r}\n  want {want!r}")


def out(f, *a, **k):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = f(*a, **k)
    return r, buf.getvalue()


tmp = tempfile.mkdtemp()
here, cwd0 = os.path.join(tmp, "here"), os.getcwd()
os.mkdir(here)
try:
    limits.NOTE, limits.LOG, limits.BOX = os.path.join(tmp, "build.md"), os.path.join(tmp, "limits.log"), "probe"
    open(limits.NOTE, "w").write(TABLE)
    _, lim = limits.tables()
    expect("tables", lim, {"whole": (100, 1000, None), "a": (60, 500, "whole"), "b": (30, 400, "whole"), "lone": (5, 5, None)})

    r, o = out(limits.split)
    expect("split fits", (r, "OVER" in o), (0, False))
    open(limits.NOTE, "w").write(TABLE.replace("| b | 30 |", "| b | 41 |"))
    r, o = out(limits.split)
    expect("split over", (r, [l.split(":")[0] for l in o.splitlines() if "OVER" in l]), (1, ["whole CPU"]))
    open(limits.NOTE, "w").write(TABLE.replace("| `whole` |", "| `nowhere` |"))
    r, o = out(limits.split)
    expect("split dangling", (r, "nowhere: no such limit" in o), (1, True))
    open(limits.NOTE, "w").write(TABLE)

    # the log: one part over here since T (the only one named), and what must not be named: a part
    # under its share, a part over before T, another directory's part over, a non-part over
    T = 1_000_000
    rec = dict(box="probe", what="", wall=1, cpu_lim=1, wall_lim=1, load=1)
    log = [dict(rec, t=T + 5, name="a", cpu=70, over=["CPU"], who=here),
           dict(rec, t=T + 6, name="b", cpu=10, over=[], who=here),
           dict(rec, t=T - 1, name="b", cpu=90, over=["CPU"], who=here),
           dict(rec, t=T + 7, name="b", cpu=90, over=["CPU"], who=os.path.join(tmp, "other")),
           dict(rec, t=T + 8, name="lone", cpu=90, over=["CPU"], who=here)]
    open(limits.LOG, "w").write("".join(json.dumps(o) + "\n" for o in log))
    os.chdir(here)
    _, o = out(limits.check, "whole", 150, 1, since=T)
    expect("over: its parts over their share", [l.strip() for l in o.splitlines() if "share of" in l],
           ["over its share of whole: `a` CPU 70/1 s at load 1"])
    _, o = out(limits.check, "whole", 50, 1, since=T)
    expect("under: no parts", "share" in o, False)
    _, o = out(limits.check, "whole", 150, 1, since=T + 6)
    expect("over, no part over since T", [l.strip() for l in o.splitlines() if "share" in l],
           ["no part of whole over its share: the time between its parts, or parts unchecked"])
    _, o = out(limits.check, "lone", 50, 1, since=T)
    expect("over, no parts at all", "share" in o, False)
finally:
    os.chdir(cwd0)
    shutil.rmtree(tmp)
print("limits_test: " + (f"{fails} FAILED" if fails else "ok"))
sys.exit(1 if fails else 0)
