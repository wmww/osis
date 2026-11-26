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

    # a cap, a share and a lone limit over: only the cap says CAP; a share is no LIMIT line
    _, o = out(limits.check, "whole", 150, 1, since=T)
    expect("cap line", [l.split(" whole ")[0] for l in o.splitlines() if l.startswith("LIMIT")], ["LIMIT CAP"])
    _, o = out(limits.check, "a", 70, 1)
    expect("share line", ([l for l in o.splitlines() if l.startswith("LIMIT")], [l.strip()[:15] for l in o.splitlines() if "over share" in l]), ([], ["over share: a C"]))
    _, o = out(limits.check, "lone", 50, 1)
    expect("lone line", [l.split(" CPU")[0] for l in o.splitlines() if l.startswith("LIMIT")], ["LIMIT lone"])

    # derive: shares from the median fractions of the last runs. A top whole `g` (100 u both) with
    # parts `h` (itself a whole), `p` and `r`; `h`'s parts `x`, `y`; `q` never measured keeps its
    # share; `lone` is reported per check, not split. Per run, in u: g 100/100; h 60/80; p 20/20
    # (checked twice: 10+10); x 30/40, y 30/20; lone 3/3 then 5/5 (12/12, 20/20 in the last). `r` ran in the last run alone,
    # g 4x as large there: 40/40 of 400/400 is a tenth, and it moves no other part's share. Older
    # runs, another directory's and checks before a run's since don't count.
    open(limits.NOTE, "w").write("""| box | unit (CPU-s) |
|---|---|
| probe | 2 |

| limit | CPU (u) | wall (u) | share of | what |
|---|---|---|---|---|
| g | 100 | 100 |  | |
| h | 50 | 50 | g | |
| p | 10 | 10 | g | |
| q | 4 | 5 | g | |
| r | 1 | 1 | g | |
| x | 10 | 10 | h | |
| y | 10 | 10 | h | |
| lone | 1 | 1 |  | |
""")
    there = os.path.join(tmp, "other")
    log = []
    for i, scale in enumerate((5, 1, 1, 4)):  # the first run is past --gates 3
        t = T + 1000 * i
        c = lambda name, cpu, wall, who=here, dt=1: log.append(dict(rec, t=t + dt, name=name, cpu=2 * cpu * scale, wall=2 * wall * scale, over=[], who=who))
        c("x", 999, 999, dt=-5)  # before the run's since
        c("x", 30, 40), c("y", 30, 20), c("p", 10, 10), c("p", 10, 10), c("lone", 3, 3), c("lone", 5, 5), c("h", 60, 80, dt=2)
        if i == 3:
            c("r", 10, 10)
        c("y", 999, 999, who=there)
        log.append(dict(rec, t=t + 3, name="g", cpu=200 * scale, wall=200 * scale, over=[], who=here, since=t))
    open(limits.LOG, "w").write("".join(json.dumps(o) + "\n" for o in log))
    r, o = out(limits.derive, 3)
    # less q's fixed share, g's 96 CPU and 95 wall: h 0.6 and 0.8 of it, p 0.2, r 0.1 CPU; the
    # wall's fractions sum to 1.1, so scaled by 1/1.1. Of h's 57 CPU and 69 wall: x 0.5 and 0.5,
    # y 0.5 and 0.25.
    expect("derive", r, {"h": (57.0, 69.0), "p": (19.0, 17.0), "q": (4, 5), "r": (9.6, 8.6), "x": (28.0, 34.0), "y": (28.0, 17.0)})
    expect("derive reports lone per check", [l.split(": ", 1)[1] for l in o.splitlines() if "`lone`" in l],
           ["CPU median 5.0, p90 20.0, most 20.0 u; wall median 5.0, p90 20.0, most 20.0 u"])

finally:
    os.chdir(cwd0)
    shutil.rmtree(tmp)
print("limits_test: " + (f"{fails} FAILED" if fails else "ok"))
sys.exit(1 if fails else 0)
