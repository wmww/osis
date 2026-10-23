#!/usr/bin/env python3
"""Give a git worktree its own cargo build dir, seeded from the main checkout's,
so its first build compiles only the path crates instead of the whole dep tree.

Checkouts must not *share* a target dir: cargo hashes path crates relative to
the workspace root, so peers write the same `deps/libfoo-<hash>.rlib`, freshness
comes down to mtimes, and one checkout can silently link another's code.

  deps/             hardlinked: rustc replaces (unlinks) artifacts, never edits
  everything else   copied: cargo edits .fingerprint/ and build/ in place
  path crates, incremental/, uplifted files, deps/*.d    skipped

Idempotent; a no-op in the main checkout or once the build dir exists, so it is
safe to run from a post-checkout hook. Run inside the new worktree.
"""
import json, os, re, shutil, subprocess, sys
from pathlib import Path

HASHED = re.compile(r"^(?:lib)?(.+)-[0-9a-f]{16}(?:\..*)?$")


def run(*cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def meta(checkout, *extra):
    out = run("cargo", "metadata", "--format-version", "1", *extra, cwd=checkout)
    return json.loads(out) if out else None


def build_dir(m):  # build.build-dir (cargo 1.91+) holds intermediates if set
    return Path(m.get("build_directory") or m["target_directory"])


def local(name):  # artifact/unit belongs to a path crate (or is unhashed)
    m = HASHED.match(name)
    return m is None or m.group(1).replace("-", "_") in LOCAL


def copy(src, dst):
    if sys.platform.startswith("linux"):
        subprocess.run(["cp", "-a", "--reflink=auto", src, dst], check=True)
    elif src.is_dir():
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)


def seed_profile(src, dst):
    dst.mkdir(parents=True)
    for e in src.iterdir():
        if e.is_file() or e.name in ("incremental", "examples"):
            continue  # uplifted outputs, locks, accelerators
        (dst / e.name).mkdir()
        for f in e.iterdir():
            if e.name == "deps":
                if not (local(f.name) or f.name.endswith(".d")):
                    os.link(f, dst / e.name / f.name)
            elif not (e.name in (".fingerprint", "build") and local(f.name)):
                copy(f, dst / e.name / f.name)


def main():
    global LOCAL
    top = run("git", "rev-parse", "--show-toplevel")
    common = run("git", "rev-parse", "--path-format=absolute", "--git-common-dir")
    if not top or not common or Path(common).name != ".git":
        return
    top, main_co = Path(top), Path(common).parent
    if top == main_co or not (top / "Cargo.toml").exists():
        return
    dm, sm = meta(top, "--no-deps"), meta(main_co, "--no-deps")
    if not dm or not sm:
        return
    src, dst = build_dir(sm), build_dir(dm)
    if src == dst:
        sys.exit(f"seed-target: checkouts share {dst}; unset CARGO_TARGET_DIR/build.target-dir")
    if dst.exists() or not src.is_dir():
        return

    pkgs = (meta(top) or dm)["packages"]
    LOCAL = {n.replace("-", "_") for p in pkgs if p.get("source") is None
             for n in [p["name"]] + [t["name"] for t in p["targets"]]}
    tmp = dst.parent / f".{dst.name}.seed.{os.getpid()}"
    try:
        tmp.mkdir(parents=True)
        for e in src.iterdir():
            subs = [d for d in e.iterdir() if (d / "deps").is_dir()] if e.is_dir() else []
            if (e / "deps").is_dir():
                seed_profile(e, tmp / e.name)
            elif subs:  # <triple>/<profile>
                for d in subs:
                    seed_profile(d, tmp / e.name / d.name)
            elif e.name == "CACHEDIR.TAG":
                copy(e, tmp / e.name)

        # Build scripts record absolute paths into the dir they ran under.
        # Rewrite only files that name it, keeping mtimes: cargo compares them
        # against consumers', and a touched one makes every dependent stale.
        old, new = str(src).encode(), str(dst).encode()
        for f in [*tmp.glob("*/build/*/*output"), *tmp.glob("*/*/build/*/*output")]:
            data = f.read_bytes()
            if old in data:
                st = f.stat()
                f.write_bytes(data.replace(old, new))
                os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.rename(tmp, dst)
        print(f"seed-target: seeded {dst} from {src}")
    except OSError as e:  # cross-filesystem link, lost race with a build, ...
        print(f"seed-target: not seeded: {e}", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
