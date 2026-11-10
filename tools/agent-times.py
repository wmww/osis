#!/usr/bin/env python3
"""Where a coordinator session's agents spent their time.

  tools/agent-times.py [SESSION] [--since HH:MM | --since YYYY-MM-DDTHH:MM+HH:MM] [--long N]

SESSION is a session's transcript dir (~/.claude/projects/<project>/<session>), its subagents/ dir
or its /tmp tasks/ dir; the default is this repo's project session that most recently ran agents.

One row per agent: total time (idle spells after it ended a turn left out), model time (no
foreground tool running: thinking and writing) and minutes per kind of work, as columns for the
kinds that took most time over all agents. A command counts from its call to its result, or for a
background one to its completion notice, so background and parallel work overlap and a row need
not add up to its total. A shell command is charged to its weightiest part: gate, sim-sweep,
oracle (--ignored, _large, seed ranges), bench, default tests (an unfiltered cargo test),
tests (filtered), clippy, tla, profile, android, build, gui, script (by its file's text), git, wt,
shell. Waiting (claudewait, poll loops) is no kind: the job waited on is counted instead. The
footer covers only agents started in the last 24 h: it totals each kind (runs, median and longest
run) and names agents that wrote wait loops. Then, from tools/heavy's log, each agent's heavy-lock use:
its waits and holds, and the CPU-s and cores its locked runs used (a run is charged to the agent whose
running command named tools/heavy or gate.sh when the run asked for the lock).
--long N lists each agent's N longest commands (a minute or more). --since HH:MM is the last such
local time (yesterday if later than now); an ISO date-time must carry its UTC offset. The watchdog
(notes/coordination.md) reads this first.
"""
import datetime as dt, glob, json, os, re, statistics, subprocess, sys

hook = sys.excepthook
sys.excepthook = lambda t, v, tb: os._exit(0) if t is BrokenPipeError else hook(t, v, tb)  # quiet under head

args, opts, it = [], {}, iter(sys.argv[1:])
for a in it:
    if a.startswith("--"):
        k, _, v = a[2:].partition("=")
        opts[k] = v if v else next(it, "")
    else:
        args.append(a)
long_n = int(opts.get("long", 0))

since = None
if "since" in opts:
    v = str(opts["since"])
    if re.fullmatch(r"\d{1,2}:\d{2}", v):
        h, m = map(int, v.split(":"))
        since = dt.datetime.now().astimezone().replace(hour=h, minute=m, second=0, microsecond=0)
        if since > dt.datetime.now().astimezone():  # a time later than now means yesterday
            since -= dt.timedelta(days=1)
    else:
        try:
            since = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            sys.exit(f"--since {v!r}: expected HH:MM or an ISO date-time with offset")
        if since.tzinfo is None:
            sys.exit(f"--since {v!r}: give the UTC offset (e.g. {v}+01:00)")


def session_dir():
    """The session's transcript dir: holds subagents/agent-*.jsonl (+ .meta.json)."""
    if args:
        p = os.path.realpath(args[0].rstrip("/"))
        if os.path.basename(p) == "tasks":  # /tmp/claude-<uid>/<project>/<session>/tasks
            proj, sess = p.split(os.sep)[-3:-1]
            p = os.path.expanduser(f"~/.claude/projects/{proj}/{sess}")
        return os.path.dirname(p) if os.path.basename(p) == "subagents" else p
    common = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip()
    proj = re.sub(r"[^A-Za-z0-9]", "-", os.path.dirname(common))
    subs = glob.glob(os.path.expanduser(f"~/.claude/projects/{proj}/*/subagents"))
    if not subs:
        sys.exit(f"no agent transcripts under ~/.claude/projects/{proj}")
    return os.path.dirname(max(subs, key=os.path.getmtime))


RANK = ["gate", "sim-sweep", "oracle", "bench", "default tests", "tests", "clippy", "tla", "profile", "android", "build", "gui",
        "cargo other", "script", "git", "wt", "shell"]
WRAP = {"do", "then", "else", "time", "nice", "ionice", "timeout", "env", "exec", "nohup", "!", "{", "(", "sudo"}


def segkind(words, c):
    """Kind of one simple command (its words, c the whole command for context)."""
    while words and (words[0] in WRAP or re.fullmatch(r"\w+=\S*", words[0]) or re.fullmatch(r"-n|-?\d+[smh]?", words[0])):
        words = words[1:]
    if not words:
        return None
    p, rest = os.path.basename(words[0]), " ".join(words[1:])
    if p in ("bash", "sh", "python3", "python") and words[1:] and not words[1].startswith("-"):
        p, rest = os.path.basename(words[1]), " ".join(words[2:])
    if p == "gate.sh":
        return "gate"
    if p in ("claudewait", "pgrep", "wait") or p == "tail" and "--pid" in rest:
        return "wait"
    if "sim-sweep" in p:
        return "sim-sweep"
    if p in ("wdotool", "grim", "slurp", "wl-copy"):
        return "gui"
    if p in ("emulator", "adb", "gradle", "gradlew") or "android" in words[0]:
        return "android"
    if p in ("run.sh", "tlc.sh", "java", "tlc") or re.search(r"tla|tlc", p):
        return "tla"
    if p in ("valgrind", "cpuprof", "perf", "callgrind_annotate"):
        return "profile"
    if p == "cargo":
        if re.search(r"\bsim-sweep\b", rest):
            return "sim-sweep"
        if re.match(r"(\+\S+ )?clippy\b", rest):
            return "clippy"
        if re.match(r"(\+\S+ )?(test|bench)\b", rest):
            if re.search(r"--no-run", rest):
                return "build"
            if re.search(r"--release", rest) and re.search(r"scale::|bench::|budget|bench", rest) or "bench" in rest.split()[:1]:
                return "bench"
            if re.search(r"--ignored|--include-ignored|_large\b", rest) or re.search(r"OSIS_\w+_(SEEDS|START)=", c):
                return "oracle"
            if re.fullmatch(r"(test)( -q| --locked| --workspace| --no-fail-fast| --jobs \d+)*", rest.strip()):
                return "default tests"
            return "tests"
        if re.match(r"(\+\S+ )?(build|check|run|doc)\b", rest):
            return "build"
        return "cargo other"
    if p == "wt":
        return "wt"
    if p == "git":
        return "git"
    if "--ignored" in rest or re.search(r"OSIS_\w+_(SEEDS|START)=", c) or "oracle" in p:
        return "oracle"  # a copied test binary or seed script
    if p.endswith(".sh") or p.endswith(".py") or "/" in words[0] and p not in ("python3", "bash"):
        return "script"
    return "shell"


def loose(text):
    """Kind of a script's text, by keyword: scripts hide their commands in variables and loops."""
    for k, pat in [("gate", r"gate\.sh"), ("sim-sweep", r"sim-sweep"), ("oracle", r"--ignored|_large\b|OSIS_\w+_(SEEDS|START)="),
                   ("bench", r"--release"), ("tla", r"\btlc|tla2tools|\.cfg\b"), ("tests", r"cargo (\+\S+ )?test\b"),
                   ("clippy", r"cargo (\+\S+ )?clippy"), ("build", r"cargo (\+\S+ )?(build|check|run)\b"), ("android", r"emulator|gradle|adb ")]:
        if re.search(pat, text):
            return k
    return "script"


HEREDOC = r"<<-?\s*'?(\w+)'?\n(.*?)\n\1\b"


def code(cmd):
    """The command without heredoc bodies and quoted strings: data, not commands run."""
    return re.sub(r"\"[^\"]*\"|'[^']*'", "''", re.sub(HEREDOC, "", cmd, flags=re.S))


def is_loop(cmd):
    c = code(cmd)
    return bool(re.search(r"\b(until|while)\b", c) and re.search(r"\bsleep\b|\bpgrep\b", c))


def kind(cmd):
    """What kind of work a shell command is (its weightiest part); None when it only waits."""
    bodies = "\n".join(b for _, b in re.findall(HEREDOC, cmd, flags=re.S))
    c = re.sub(HEREDOC, "", cmd, flags=re.S)
    if "claudewait" in code(cmd) or is_loop(cmd):
        return None
    env = dict(re.findall(r"(?:^|[\s;&(])(\w+)=([^\s;&|()'\"]+)", c))
    c = re.sub(r"\$\{?(\w+)\}?", lambda m: env.get(m.group(1), m.group(0)), c)
    c = re.sub(r"\"[^\"]*\"|'[^']*'", "''", c)
    c = re.sub(r"\d*(>>?|<)&?\s*(\d\b|[^\s;&|()]+)", " ", c)  # redirections
    ks, waits = [], False
    for seg in re.split(r"&&|\|\||[;|&\n()`]|\$\(", c):
        k = segkind(seg.split(), c)
        if k == "script":
            words = [w for w in seg.split() if "/" in w or w.endswith(".sh")]
            try:
                text = open(os.path.expanduser(words[0]), "rb").read(100000) if words else b""
                k = "tests" if b"\0" in text else loose(text.decode(errors="replace")) if text else k  # binary: a copied test binary
            except OSError:
                k = loose(bodies) if bodies else k
        if k == "wait":
            waits = True
        elif k:
            ks.append(k)
    k = min(ks, key=RANK.index) if ks else None
    return None if waits and k in (None, "shell", "git") else k


TOOL_KINDS = {"Read": "files", "Edit": "files", "Write": "files", "Grep": "files", "Glob": "files",
              "NotebookEdit": "files", "Agent": "agents", "Task": "agents", "WebFetch": "web", "WebSearch": "web"}


def ts(o):
    t = o.get("timestamp")
    return dt.datetime.fromisoformat(t.replace("Z", "+00:00")) if t else None


def union(iv):
    out = []
    for s, e in sorted(iv):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def clip(iv, spans):
    """Seconds of the union of iv that lie inside spans (both sorted, disjoint after union)."""
    tot = 0.0
    for s, e in union(iv):
        for a, b in spans:
            lo, hi = max(s, a), min(e, b)
            if hi > lo:
                tot += (hi - lo).total_seconds()
    return tot


def analyze(path):
    meta = {}
    try:
        meta = json.load(open(path[:-len(".jsonl")] + ".meta.json"))
    except (OSError, ValueError):
        pass
    uses, res, done, stops = {}, {}, {}, set()
    events, idle_from, idle = [], None, []  # idle: (end_turn time, next prompt time)
    first_prompt = None
    for line in open(path):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        t = ts(o)
        if not t:
            continue
        events.append(t)
        for tid in re.findall(r"<task-id>(\w+)</task-id>", line):  # background completion notice
            done.setdefault(tid, t)
        if o.get("type") == "attachment":
            continue
        msg = o.get("message", {})
        c = msg.get("content")
        if o.get("type") == "user":
            is_prompt = isinstance(c, str) or not any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c or [])
            if is_prompt and first_prompt is None:
                first_prompt = c if isinstance(c, str) else " ".join(b.get("text", "") for b in c if isinstance(b, dict))
            if is_prompt and idle_from:
                idle.append((idle_from, t))
            idle_from = None
        elif o.get("type") == "assistant":
            idle_from = t if msg.get("stop_reason") == "end_turn" else None
        if not isinstance(c, list):
            continue
        for b in c:
            if b.get("type") == "tool_use":
                uses.setdefault(b["id"], (t, b["name"], b.get("input") or {}))
                if b["name"] in ("TaskStop", "KillShell"):
                    stops.add(b["id"])
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in uses and b["tool_use_id"] not in res:
                rc = b.get("content")
                rc = " ".join(x.get("text", "") for x in rc if isinstance(x, dict)) if isinstance(rc, list) else str(rc)
                res[b["tool_use_id"]] = (t, rc)
    if not uses:
        return None
    t0, t1 = min(events), max(events)
    if since and t0 < since:
        return None
    spans, s = [], t0
    for a, b in sorted(idle):
        if a > s:
            spans.append((s, a))
        s = max(s, b)
    spans.append((s, t1))
    for i in stops:  # a stopped background job ends at the stop
        tid = (uses[i][2] or {}).get("task_id") or (uses[i][2] or {}).get("shell_id")
        if tid and i in res:
            done.setdefault(tid, res[i][0])
    tasks_dir = os.path.join(f"/tmp/claude-{os.getuid()}", *path.split(os.sep)[-4:-2], "tasks")
    fg, kinds, cmds, bash = [], {}, [], []
    loops = moved = 0
    for i, (t, name, inp) in uses.items():
        if i not in res:
            continue
        rt, r = res[i]
        fg.append((t, rt))
        cmd = inp.get("command", "") if name == "Bash" else ""
        k = kind(cmd) if name == "Bash" else TOOL_KINDS.get(name, "tools")
        end = rt
        m = re.search(r"(?:running in background with ID|moved to the background[^\n]*?ID): (\w+)", r)
        if name == "Bash" and m:
            tid = m.group(1)
            end = done.get(tid)
            if end is None:  # no notice: the output file's last write, else the agent's end
                try:
                    end = dt.datetime.fromtimestamp(os.path.getmtime(os.path.join(tasks_dir, tid + ".output")), dt.timezone.utc)
                except OSError:
                    end = t1
            end = max(rt, min(end, t1))
        if name == "Bash":
            bash.append((t, end, cmd))
        if name == "Bash" and is_loop(cmd):
            loops += 1
        if re.match(r"Command (was moved to the background|did not complete within its)", r):
            moved += 1
        if k is None:
            continue
        kinds.setdefault(k, []).append((t, end))
        cmds.append(((end - t).total_seconds(), k, cmd or inp.get("description", "") or inp.get("file_path", "")))
    total = sum((b - a).total_seconds() for a, b in spans)
    model = total - clip(fg, spans)
    cmds.sort(key=lambda x: -x[0])
    runs = {k: [(e - s).total_seconds() for s, e in v] for k, v in kinds.items()}
    name = meta.get("description") or (first_prompt or os.path.basename(path))[:50].replace("\n", " ")
    if meta.get("model") and meta["model"] != "opus":
        name += f" [{meta['model']}]"
    return dict(name=name, start=t0, end=t1, total=total, model=model, kinds={k: clip(v, spans) for k, v in kinds.items()},
                runs=runs, loops=loops, moved=moved, cmds=cmds, bash=bash)


sess = session_dir()
rows = [a for a in (analyze(p) for p in glob.glob(os.path.join(sess, "subagents", "*.jsonl"))) if a]
rows.sort(key=lambda a: a["start"])
if not rows:
    sys.exit(f"no agents in {sess}" + (f" since {since}" if since else ""))

tot = {}
for a in rows:
    for k, v in a["kinds"].items():
        tot[k] = tot.get(k, 0.0) + v
MAXCOLS = 9
cols = [k for k, _ in sorted(tot.items(), key=lambda kv: -kv[1])]
cols, rest = cols[:MAXCOLS], cols[MAXCOLS:]
if rest:
    cols.append("other")


def m(sec):
    return f"{sec/60:.0f}" if sec >= 30 else "."


def day(t):
    return t.astimezone().strftime("%d %H:%M")


def short(cmd):
    """A command as a person would retype it: no leading cd, scratch paths shortened."""
    cmd = re.sub(r"/tmp/claude-\d+/[^/\s]+/[^/\s]+/(scratchpad|tasks)/", r"<\1>/", cmd)
    cmd = re.sub(r"^(cd \S+ *(&&|;) *|export PATH=\S+ *(&&|;) *)+", "", cmd)
    return cmd.replace("\n", " ")[:120]


print(f"{len(rows)} agents, {day(rows[0]['start'])} to {day(max(a['end'] for a in rows))}. Minutes per agent; "
      f"model = no foreground tool running (thinking, writing). Background and parallel work overlap, "
      f"so a row need not add up to its total.\n")
print(f"{'start':8s} {'total':>5s} {'model':>5s} " + " ".join(f"{c[:7]:>7s}" for c in cols) + "  agent")
for a in rows:
    ks = a["kinds"]
    vals = [ks.get(c, 0.0) for c in cols if c != "other"] + ([sum(ks.get(k, 0.0) for k in rest)] if rest else [])
    print(f"{day(a['start']):8s} {m(a['total']):>5s} {m(a['model']):>5s} " + " ".join(f"{m(v):>7s}" for v in vals) + f"  {a['name']}")
    for d, k, cmd in [c for c in a["cmds"] if c[0] >= 60][:long_n]:
        print(f"{'':8s} {d/60:5.1f} {k:>11s}  {short(cmd)}")

def footer():
    recent = [a for a in rows if a["start"] >= dt.datetime.now().astimezone() - dt.timedelta(hours=24)]
    if not recent:
        print("\nno agents started in the last 24 h: no summary")
        return
    tot = {}
    for a in recent:
        for k, v in a["kinds"].items():
            tot[k] = tot.get(k, 0.0) + v
    T = sum(a["total"] for a in recent)
    M = sum(a["model"] for a in recent)
    print(f"\nlast 24 h, {len(recent)} agents: {T/60:.0f} agent-minutes, median agent {statistics.median(a['total'] for a in recent)/60:.0f} min"
          + (f"; 'other' is {', '.join(rest)}" if rest else ""))
    print(f"{'kind':12s} {'minutes':>8s} {'% of total':>10s} {'runs':>6s} {'median run':>10s} {'longest':>8s}")
    print(f"{'model':12s} {M/60:8.0f} {100*M/T:9.0f}%")
    for k, sec in sorted(tot.items(), key=lambda kv: -kv[1]):
        if sec < 30:
            continue
        r = [x for a in recent for x in a["runs"].get(k, [])]
        print(f"{k:12s} {sec/60:8.0f} {100*sec/T:9.0f}% {len(r):6d} {statistics.median(r)/60:10.1f} {max(r)/60:8.1f}")
    moved = sum(a["moved"] for a in recent)
    if moved:
        print(f"\n{moved} foreground calls outlived their timeout or the 180 s subagent cap and moved to the background")
    bad = [a for a in recent if a["loops"]]
    if bad:
        print("wait loops (until/while + sleep, pgrep) instead of claudewait:")
        for a in bad:
            print(f"  {a['loops']:3d}  {day(a['start'])}  {a['name']}")


footer()

def heavy_runs():
    """tools/heavy's finished runs in this session: (acq, rel) event pairs."""
    log = os.path.expanduser("~/.cache/osis/heavy.log")
    open_, out = {}, []
    for path in (log + ".1", log):
        try:
            lines = open(path).readlines()
        except OSError:
            continue
        for line in lines:
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if o.get("sess") and o["sess"] != os.path.basename(sess):
                continue
            if o["ev"] == "acq":
                open_[o["pid"]] = o
            elif o["ev"] == "rel" and o["pid"] in open_:
                out.append((open_.pop(o["pid"]), o))
    return out


def charge(runs):
    """Each run's agent: one whose Bash command naming tools/heavy or gate.sh was running when the run
    asked for the lock; the run's worktree in the command breaks ties."""
    per, lost = {}, 0
    for a, r in runs:
        asked = dt.datetime.fromtimestamp(a["t"] - a["wait"], dt.timezone.utc)
        cands = [(row, cmd) for row in rows for s, e, cmd in row["bash"]
                 if s <= asked <= e + dt.timedelta(seconds=5) and re.search(r"\bheavy\b|gate\.sh", cmd)]
        if not cands:
            lost += 1
            continue
        row = next((row for row, cmd in cands if a["who"] in cmd), cands[0][0])
        per.setdefault(id(row), (row, []))[1].append((a, r))
    return per, lost


hr = heavy_runs()
if hr:
    per, lost = charge(hr)
    ncpu = os.cpu_count()
    print(f"\nheavy lock (tools/heavy --report for the box view): minutes waiting and holding, the locked runs' CPU-s, "
          f"cores they used on average (CPU-s / held) and that as a share of {ncpu}")
    print(f"{'start':8s} {'total':>5s} {'runs':>4s} {'wait':>5s} {'held':>5s} {'CPU-s':>7s} {'cores':>5s} {'util':>4s}  agent")
    for row, rs in sorted(per.values(), key=lambda x: x[0]["start"]):
        w, h, c = (sum(a["wait"] for a, _ in rs), sum(r["held"] for _, r in rs), sum(r["cpu"] for _, r in rs))
        print(f"{day(row['start']):8s} {m(row['total']):>5s} {len(rs):4d} {w/60:5.1f} {h/60:5.1f} {c:7.0f} "
              f"{c / h if h else 0:5.1f} {100 * c / (h * ncpu) if h else 0:3.0f}%  {row['name']}")
    if lost:
        print(f"{lost} locked runs in this session matched no agent's command (the coordinator's own, or before --since)")
