//! vectors/MANIFEST: every vector file with its status, and the freeze policy (README.md).
//! Line form: `path provisional` | `path frozen <blake3 hex> <FC-n>` | `path pending <reason>`.

use crate::{hex, root};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Listed but not yet producible (its crate or a spec alignment has not landed).
    Pending(String),
    /// Present, checked, may change with the implementation.
    Provisional,
    /// Present, checked, and its bytes may change only under a FORMAT_CHANGES.md entry.
    Frozen { blake3: String, change: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub status: Status,
}

pub fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let mut out: Vec<Entry> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (path, status) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        let rest: Vec<&str> = it.collect();
        let status = match (status, rest.as_slice()) {
            ("provisional", []) => Status::Provisional,
            ("frozen", [h, c]) => Status::Frozen { blake3: h.to_string(), change: c.to_string() },
            ("pending", r) if !r.is_empty() => Status::Pending(r.join(" ")),
            _ => return Err(format!("MANIFEST line {}: bad entry `{line}`", n + 1)),
        };
        if out.iter().any(|e| e.path == path) {
            return Err(format!("MANIFEST: duplicate {path}"));
        }
        out.push(Entry { path: path.to_string(), status });
    }
    Ok(out)
}

pub fn load() -> Result<Vec<Entry>, String> {
    parse(&std::fs::read_to_string(root().join("MANIFEST")).map_err(|e| format!("MANIFEST: {e}"))?)
}

pub fn file_hash(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(root().join(path)).map_err(|e| format!("{path}: {e}"))?;
    Ok(hex(&osis_core::hash::hash(&bytes)))
}

fn vec_files(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            vec_files(&p, base, out);
        } else if p.extension().is_some_and(|x| x == "vec")
            && let Ok(rel) = p.strip_prefix(base)
        {
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The section `## <change>` of FORMAT_CHANGES.md, up to the next `## `.
fn change_section(changes: &str, change: &str) -> Option<String> {
    let head = format!("## {change}");
    let start = changes.lines().position(|l| l.strip_prefix(&head).is_some_and(|r| r.is_empty() || r.starts_with([':', ' '])))?;
    let body: Vec<&str> = changes.lines().skip(start + 1).take_while(|l| !l.starts_with("## ")).collect();
    Some(body.join("\n"))
}

/// Every policy rule of README.md, "Manifest and freezing". Returns all violations.
pub fn check(entries: &[Entry]) -> Vec<String> {
    let mut errs = Vec::new();
    let mut files = BTreeSet::new();
    vec_files(&root(), &root(), &mut files);
    let changes = std::fs::read_to_string(root().join("FORMAT_CHANGES.md")).unwrap_or_default();
    for f in &files {
        if !entries.iter().any(|e| &e.path == f) {
            errs.push(format!("{f}: not in MANIFEST"));
        }
    }
    for e in entries {
        let exists = files.contains(&e.path);
        match &e.status {
            Status::Pending(_) if exists => errs.push(format!("{}: pending but present; mark it provisional", e.path)),
            Status::Pending(_) => {}
            _ if !exists => errs.push(format!("{}: listed but missing", e.path)),
            Status::Provisional => {}
            Status::Frozen { blake3, change } => {
                match file_hash(&e.path) {
                    Ok(h) if &h == blake3 => {}
                    Ok(h) => errs.push(format!(
                        "{}: frozen vector changed (blake3 {h}); a change needs a FORMAT_CHANGES.md entry and a new MANIFEST hash",
                        e.path
                    )),
                    Err(err) => errs.push(err),
                }
                match change_section(&changes, change) {
                    Some(body) if body.contains(&e.path) => {}
                    Some(_) => errs.push(format!("{}: FORMAT_CHANGES.md {change} does not name it", e.path)),
                    None => errs.push(format!("{}: FORMAT_CHANGES.md has no `## {change}`", e.path)),
                }
                if let Ok(text) = std::fs::read_to_string(root().join(&e.path))
                    && text.lines().any(|l| l.starts_with("pending: "))
                {
                    errs.push(format!("{}: frozen file has pending cases", e.path));
                }
            }
        }
    }
    errs
}

/// Marks `path` frozen at its current bytes under FORMAT_CHANGES.md entry `change`.
pub fn freeze(path: &str, change: &str) -> Result<(), String> {
    let mpath = root().join("MANIFEST");
    let text = std::fs::read_to_string(&mpath).map_err(|e| e.to_string())?;
    let h = file_hash(path)?;
    let mut found = false;
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            if l.split_whitespace().next() == Some(path) {
                found = true;
                format!("{path} frozen {h} {change}")
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        return Err(format!("{path}: not in MANIFEST"));
    }
    std::fs::write(&mpath, lines.join("\n") + "\n").map_err(|e| e.to_string())
}
