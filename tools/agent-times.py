#!/usr/bin/env python3
"""Where a coordinator session's agents spent their time, from the Bash tool's task transcripts.

  tools/agent-times.py [TASKS_DIR] [--since HH:MM] [--long N]

TASKS_DIR is the session's tasks directory (/tmp/claude-<uid>/<project>/<session>/tasks); the
default is the most recently modified one. Per agent: wall time, model time (gaps between a tool
result and the next call: thinking and editing), time in cargo commands, in `claudewait`, in other
shell commands; calls moved to the background at the harness's 180 s subagent cap, calls that hit
their timeout, shell wait loops (until/while + sleep, pgrep), and the longest calls (--long N,
default 3). The watchdog (notes/coordination.md) reads this first.
"""
import datetime as dt, glob, json, os, re, sys

args, opts, it = [], {}, iter(sys.argv[1:])
for a in it:
    if a.startswith("--"):
        k, _, v = a[2:].partition("=")
        opts[k] = v if v else next(it, "")
    else:
        args.append(a)
long_n = int(opts.get("long", 3))
tasks = args[0] if args else max(glob.glob(f"/tmp/claude-{os.getuid()}/*/*/tasks"), key=os.path.getmtime)
since = None
if "since" in opts:
    h, m = map(int, str(opts["since"]).split(":"))
    since = dt.datetime.now().astimezone().replace(hour=h, minute=m, second=0, microsecond=0)


def ts(o):
    t = o.get("timestamp")
    return dt.datetime.fromisoformat(t.replace("Z", "+00:00")) if t else None


def analyze(path):
    uses, order, res, title = {}, [], {}, None
    for line in open(path):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        t, c = ts(o), o.get("message", {}).get("content")
        if title is None and o.get("type") == "user" and isinstance(c, str):
            title = c[:60].replace("\n", " ")
        if not t or not isinstance(c, list):
            continue
        for b in c:
            if b.get("type") == "tool_use":
                uses[b["id"]] = (t, b["name"], b.get("input") or {})
                order.append(b["id"])
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in uses:
                rc = b.get("content")
                rc = " ".join(x.get("text", "") for x in rc if isinstance(x, dict)) if isinstance(rc, list) else str(rc)
                res[b["tool_use_id"]] = (t, rc)
    if not order:
        return None
    t0 = uses[order[0]][0]
    if since and t0 < since:
        return None
    end = max((res[i][0] for i in order if i in res), default=t0)
    wall = (end - t0).total_seconds()
    cat = {"cargo": 0.0, "claudewait": 0.0, "shell": 0.0, "tools": 0.0}
    moved = timeouts = loops = 0
    model = 0.0
    last_res = None
    longest = []
    for i in order:
        t, name, inp = uses[i]
        if last_res is not None:
            model += (t - last_res).total_seconds()
            last_res = None
        if i not in res:
            continue
        d = (res[i][0] - t).total_seconds()
        last_res = res[i][0]
        r = res[i][1]
        cmd = inp.get("command", "") if isinstance(inp, dict) else ""
        if name != "Bash":
            cat["tools"] += d
        elif "claudewait" in cmd:
            cat["claudewait"] += d
        elif re.search(r"\bcargo\b", cmd):
            cat["cargo"] += d
        else:
            cat["shell"] += d
        if "moved to the background" in r and "after running for 180" in r:
            moved += 1
        if "did not complete within its" in r:
            timeouts += 1
        if re.search(r"\b(until|while)\b.*\bsleep\b", cmd) or "pgrep" in cmd:
            loops += 1
        longest.append((d, name, (cmd or inp.get("description", "") or "")[:90].replace("\n", " ")))
    longest.sort(reverse=True)
    return dict(title=title or os.path.basename(path), start=t0.astimezone().strftime("%H:%M"), wall=wall, model=model,
                cat=cat, moved=moved, timeouts=timeouts, loops=loops, longest=longest[:long_n], calls=len(order))


rows = [a for a in (analyze(p) for p in sorted(glob.glob(os.path.join(tasks, "a*.output")), key=os.path.getmtime)) if a]
print(f"{'start':5s} {'wall':>5s} {'model':>6s} {'cargo':>6s} {'wait':>6s} {'shell':>6s} {'calls':>5s} {'180s':>4s} {'t/o':>3s} {'loop':>4s}  agent")
for a in rows:
    c = a["cat"]
    print(f"{a['start']:5s} {a['wall']/60:5.0f} {a['model']/60:6.1f} {c['cargo']/60:6.1f} {c['claudewait']/60:6.1f} {c['shell']/60:6.1f} "
          f"{a['calls']:5d} {a['moved']:4d} {a['timeouts']:3d} {a['loops']:4d}  {a['title']}")
    for d, name, cmd in a["longest"]:
        if d >= 120:
            print(f"      {d/60:5.1f} min  {name:6s} {cmd}")
if rows:
    W = sum(a["wall"] for a in rows); M = sum(a["model"] for a in rows)
    print(f"\n{len(rows)} agents, {W/60:.0f} agent-minutes, model {100*M/W:.0f}%, "
          f"{sum(a['loops'] for a in rows)} wait loops, {sum(a['timeouts'] for a in rows)} timeouts, {sum(a['moved'] for a in rows)} calls moved at 180 s (minutes)")
