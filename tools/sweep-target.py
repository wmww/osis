#!/usr/bin/env python3
"""Delete orphaned artifacts from this workspace's cargo build dir.

cargo never GCs: every profile/flag/feature change, dep bump, toolchain upgrade
or build-script rerun orphans the previous artifacts forever. mtime-based tools
(cargo-sweep) can't tell live from orphaned. This asks cargo for the live set
(build with --message-format=json, collect every unit hash) and deletes hashed
entries nothing references. Over-deleting only ever costs a rebuild.

Only profile dirs the invocations below touch are swept. Add the project's
other canonical invocation shapes with --also, e.g.
  --also "build -p app --release --no-default-features"
incremental/ can't be liveness-matched (its dirs are named by crate name and a
hash of their own): per profile and crate name it keeps as many of the newest
dirs as there are live units of that name (--drop-incremental drops it all).

Usage: sweep-target.py [--dry-run] [--drop-incremental] [--no-defaults] [--also "ARGS"]...
"""
import argparse, fcntl, json, re, shlex, shutil, subprocess, sys
from pathlib import Path

HASH = re.compile(r"-([0-9a-f]{16})(?:\.|$)")
UNITS = ("deps", "build", ".fingerprint", "examples")


def norm(name):
    return name.removeprefix("lib").replace("-", "_")


def pkg_names(msg):  # package_id: "name 1.0 (src)" or "src#name@1.0" or "src/name#1.0"
    pid = msg["package_id"]
    if " " in pid:
        pkg = pid.split()[0]
    else:
        src, frag = pid.rsplit("#", 1)
        pkg = frag.split("@")[0] if "@" in frag else src.rstrip("/").rsplit("/", 1)[-1]
    return pkg, msg["target"]["name"]


def real_size(p):  # bytes actually freed: hardlinked files are shared with peers
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    return sum(s.st_size for s in map(Path.lstat, files) if s.st_nlink == 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--drop-incremental", action="store_true")
    ap.add_argument("--also", action="append", default=[], metavar="ARGS")
    ap.add_argument("--no-defaults", action="store_true", help="only the --also shapes")
    a = ap.parse_args()
    m = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                  capture_output=True, text=True, check=True).stdout)
    root = Path(m.get("build_directory") or m["target_directory"])
    shapes = [] if a.no_defaults else ["build --workspace --all-targets"]
    if not a.no_defaults and (root / "release").is_dir():
        shapes.append("build --workspace --all-targets --release")  # covers `cargo test --release` binaries
    live, profiles, inodes, names = set(), set(), set(), set()
    units = {}  # (profile dir, crate name) -> live units: bounds incremental/
    for shape in shapes + a.also:
        words = shlex.split(shape)
        cut = words.index("--") if "--" in words else len(words)  # keep `-- args` last
        p = subprocess.run(["cargo", *words[:cut], "--message-format=json", *words[cut:]],
                           capture_output=True, text=True)
        if p.returncode:
            sys.exit(f"sweep-target: `cargo {shape}` failed, not sweeping:\n{p.stderr[-2000:]}")
        for line in p.stdout.splitlines():
            msg = json.loads(line) if line.startswith("{") else {}
            paths = msg.get("filenames") or []
            if msg.get("out_dir"):
                paths.append(msg["out_dir"])
            if msg.get("reason") == "compiler-artifact" and msg["filenames"]:
                prof = next((d.parent for d in Path(msg["filenames"][0]).parents if d.name in UNITS), None)
                key = (prof, norm(msg["target"]["name"]))
                units[key] = units.get(key, 0) + 1
            for f in map(Path, paths):
                for part in f.parts:
                    live.update(HASH.findall(part))
                profiles.update(d.parent for d in f.parents if d.name in UNITS)
                if HASH.search(f.name) or not f.exists():
                    continue
                if f.parent.name == "deps" or (f.parent / "deps" / f.name).exists():
                    names.update(map(norm, pkg_names(msg)))  # (c)dylib: no hash anywhere
                elif (f.parent / "deps").is_dir():
                    inodes.add(f.stat().st_ino)  # uplifted bin: deps/ twin shares the inode
                    profiles.add(f.parent)

    doomed = []
    for prof in profiles:
        for f in (prof / "deps").glob("*"):
            if f.stat().st_ino in inodes:
                live.update(HASH.findall(f.name))
        for sub in UNITS:
            for e in (prof / sub).iterdir() if (prof / sub).is_dir() else []:
                h = HASH.search(e.name)
                if h and h.group(1) not in live and norm(e.name[:h.start()]) not in names:
                    doomed.append(e)
        by_crate = {}
        for e in (prof / "incremental").glob("*"):
            by_crate.setdefault(e.name.rsplit("-", 1)[0], []).append(e)
        for crate, dirs in by_crate.items():
            dirs.sort(key=lambda e: e.stat().st_mtime, reverse=True)
            keep = 0 if a.drop_incremental else units.get((prof, crate), 0)
            doomed += dirs[keep:]

    freed = sum(map(real_size, doomed))
    if not a.dry_run:
        held = []  # cargo's own build locks: no build can run while we delete
        for lock in [f for p in profiles for f in p.glob(".cargo*lock")]:
            held.append(open(lock, "a"))
            try:
                fcntl.flock(held[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                sys.exit("sweep-target: a build is running in this dir; retry when it's done")
        for e in doomed:
            shutil.rmtree(e) if e.is_dir() else e.unlink()
    others = [d for d in root.glob("*") if d.is_dir()
              and not any(p == d or p.parent == d for p in profiles)]
    print(f"sweep-target: {'would free' if a.dry_run else 'freed'} {freed / 2**20:.0f} MiB "
          f"({len(doomed)} entries) in {root}: {' '.join(sorted(str(p.relative_to(root)) for p in profiles))}")
    if others:
        print("not swept (no invocation touches them):", *(d.name for d in others))


if __name__ == "__main__":
    main()
