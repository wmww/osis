//! The opt-in per-node trace (notes/sync-test-harness.md, Trace): `OSIS_SYNC_TRACE=<nodes>[:<only>]`
//! prints, for each delivery to a named node, what it received, what it sent (decoded messages,
//! after any lie), and what the step applied (store entries and engine commits gained or lost),
//! plus each script step played. `<nodes>` is `all` or node indices joined by `,`; `<only>`,
//! tokens joined by `,`, keeps the lines holding any of them: `t<k>` stands for thing k's sync
//! IDs (as `S` and 6 hex digits), any other token is matched as text (`S1a2b3c`, `B..`, `Stream`).
//! Off (unset), the world holds no tracer and pays one branch per delivery. Lines are a function
//! of the seed: delivery number, world time since the start, node indices.

use osis_base::{BlobId, CommitId, SyncId};
use osis_proto::{FrameDecoder, Msg};
use osis_sync::{ConnId, Input, Out};
use std::collections::{BTreeMap, BTreeSet};

/// The variable that turns the trace on.
pub const TRACE_VAR: &str = "OSIS_SYNC_TRACE";

/// What a node held after its last traced step.
#[derive(Clone, Default)]
struct Held {
    entries: BTreeSet<(SyncId, BlobId)>,
    commits: BTreeSet<CommitId>,
}

/// One world's trace.
#[derive(Clone)]
pub struct Tracer {
    /// Traced nodes; `None`: all.
    nodes: Option<BTreeSet<usize>>,
    only: Vec<String>,
    /// Frames per (node, its conn, sent), and whether the Hello went by.
    frames: BTreeMap<(usize, ConnId, bool), (FrameDecoder, bool)>,
    held: BTreeMap<usize, Held>,
    /// Lines of the step being traced.
    lines: Vec<String>,
}

impl Tracer {
    /// The tracer `OSIS_SYNC_TRACE` asks for, if any.
    pub fn from_env() -> Option<Tracer> {
        osis_base::testenv::check_known();
        Tracer::parse(&std::env::var(TRACE_VAR).ok()?)
    }

    /// `<nodes>[:<only>]`; `None` for an empty spec.
    pub fn parse(spec: &str) -> Option<Tracer> {
        let (nodes, only) = spec.split_once(':').unwrap_or((spec, ""));
        let nodes = match nodes.trim() {
            "" => return None,
            "all" => None,
            ns => Some(ns.split(',').map(|n| n.trim().parse().unwrap_or_else(|_| panic!("{TRACE_VAR}: {n:?} is no node index"))).collect()),
        };
        let only = only.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
        Some(Tracer { nodes, only, frames: BTreeMap::new(), held: BTreeMap::new(), lines: Vec::new() })
    }

    pub fn traces(&self, i: usize) -> bool {
        self.nodes.as_ref().is_none_or(|n| n.contains(&i))
    }

    /// Thing tokens (`t<k>`) of the filter.
    pub fn things(&self) -> Vec<usize> {
        self.only.iter().filter_map(|t| t.strip_prefix('t')?.parse().ok()).collect()
    }

    /// Node `i` is handed `input`, on a connection whose other end is `peer`'s.
    pub fn received(&mut self, i: usize, input: &Input, peer: Option<usize>) {
        let from = peer.map_or(String::new(), |p| format!(" n{p}"));
        let line = match input {
            Input::Bytes { conn, bytes } => {
                for m in self.decode(i, *conn, false, bytes) {
                    self.lines.push(format!("n{i} <-{from} {}: {m}", c(*conn)));
                }
                return;
            }
            Input::Up { conn, rank, dialed, .. } => format!("n{i} up{from} {} rank {rank}{}", c(*conn), if *dialed { " dialed" } else { "" }),
            Input::Taken { .. } => return,
            Input::Closed { conn } => format!("n{i} closed{from} {}", c(*conn)),
            Input::Down { conn } => format!("n{i} down {}", c(*conn)),
            Input::Tick { .. } => format!("n{i} tick"),
            Input::Wrote => format!("n{i} wrote"),
            Input::Discovered { addr } => format!("n{i} discovered {}", hex(&addr.key)),
        };
        self.lines.push(line);
    }

    /// Node `i`'s outputs, as carried (`peer` names each connection's other end).
    pub fn sent(&mut self, i: usize, out: &[Out], peer: impl Fn(ConnId) -> Option<usize>) {
        for o in out {
            match o {
                Out::Send(conn, bytes) => {
                    let to = peer(*conn).map_or(String::new(), |p| format!(" n{p}"));
                    for m in self.decode(i, *conn, true, bytes) {
                        self.lines.push(format!("n{i} ->{to} {}: {m}", c(*conn)));
                    }
                }
                Out::Dial(conn, to) => self.lines.push(format!("n{i} dial {} {}", c(*conn), hex(&to.key))),
                Out::Close(conn) => {
                    self.frames.retain(|(n, c, _), _| (*n, *c) != (i, *conn));
                    self.lines.push(format!("n{i} close {}", c(*conn)));
                }
                Out::Wake(_) => {}
            }
        }
    }

    /// What node `i` holds now against what it held at its last traced step.
    pub fn applied(&mut self, i: usize, entries: BTreeSet<(SyncId, BlobId)>, commits: BTreeSet<CommitId>) {
        let was = self.held.remove(&i).unwrap_or_default();
        for (s, b) in entries.difference(&was.entries) {
            self.lines.push(format!("n{i} +entry {} {}", brief(&format!("{s:?}")), brief(&format!("{b:?}"))));
        }
        for (s, b) in was.entries.difference(&entries) {
            self.lines.push(format!("n{i} -entry {} {}", brief(&format!("{s:?}")), brief(&format!("{b:?}"))));
        }
        for c in commits.difference(&was.commits) {
            self.lines.push(format!("n{i} +commit {}", brief(&format!("{c:?}"))));
        }
        for c in was.commits.difference(&commits) {
            self.lines.push(format!("n{i} -commit {}", brief(&format!("{c:?}"))));
        }
        self.held.insert(i, Held { entries, commits });
    }

    /// Node `i` restarted: its connections' frames are gone.
    pub fn restarted(&mut self, i: usize) {
        self.frames.retain(|(n, ..), _| *n != i);
        self.lines.push(format!("n{i} restarted"));
    }

    /// Prints the step's lines that pass the filter (`things`: the text thing tokens stand for),
    /// headed by delivery `d` at `ms` since the start.
    pub fn flush(&mut self, d: u64, ms: u64, things: &[String]) {
        let lines = std::mem::take(&mut self.lines);
        if osis_base::testenv::quiet() {
            return;
        }
        for l in lines {
            if self.only.is_empty() || self.only.iter().filter(|t| !is_thing(t)).chain(things).any(|t| l.contains(t.as_str())) {
                eprintln!("d{d} +{ms}ms {l}");
            }
        }
    }

    /// The messages of `bytes` on node `i`'s `conn` (`sent`: its own), the Hello skipped.
    fn decode(&mut self, i: usize, conn: ConnId, sent: bool, bytes: &[u8]) -> Vec<String> {
        let (f, hello) = self.frames.entry((i, conn, sent)).or_insert_with(|| (FrameDecoder::default(), false));
        f.push(bytes);
        let mut out = Vec::new();
        while let Ok(Some(body)) = f.next_frame() {
            if !std::mem::replace(hello, true) {
                out.push("Hello".to_string());
                continue;
            }
            out.push(match Msg::decode(&body) {
                Ok(m) => brief(&format!("{m:?}")),
                Err(e) => format!("undecodable ({e:?}, {} bytes)", body.len()),
            });
        }
        out
    }
}

/// A connection end as the trace prints it: `c<n>` dialed, `a<n>` accepted.
fn c(conn: ConnId) -> String {
    if conn.accepted() { format!("a{}", conn.0 & !ConnId::ACCEPTED) } else { format!("c{}", conn.0) }
}

fn is_thing(t: &str) -> bool {
    t.strip_prefix('t').is_some_and(|k| k.parse::<usize>().is_ok())
}

/// A sync ID as the trace prints it.
pub fn short(s: &SyncId) -> String {
    brief(&format!("{s:?}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().take(3).map(|x| format!("{x:02x}")).collect()
}

/// Lines longer than this are cut (a message's Debug can carry whole blobs).
const LINE_MAX: usize = 400;

/// A Debug string made compact: `SyncId(1a2b3c..)` as `S1a2b3c`, `BlobId` as `B..`, `CommitId` as
/// `C..`; a list of more than 8 numbers (bytes) as `[N b]`; cut at `LINE_MAX`.
pub fn brief(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(LINE_MAX));
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        let id = [("SyncId(", 'S'), ("BlobId(", 'B'), ("CommitId(", 'C')].into_iter().find(|(p, _)| rest.starts_with(p));
        if let Some((p, letter)) = id {
            let body = &rest[p.len()..];
            let end = body.find(')').unwrap_or(body.len());
            out.push(letter);
            out.extend(body[..end].chars().filter(char::is_ascii_hexdigit).take(6));
            rest = body.get(end + 1..).unwrap_or("");
            continue;
        }
        if c == '['
            && let Some(end) = rest.find(']')
        {
            let inner = &rest[1..end];
            if inner.chars().all(|c| c.is_ascii_digit() || c == ',' || c == ' ') && inner.split(',').count() > 8 {
                out.push_str(&format!("[{} b]", inner.split(',').count()));
                rest = &rest[end + 1..];
                continue;
            }
        }
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    if out.len() > LINE_MAX {
        let cut = (0..=LINE_MAX).rev().find(|i| out.is_char_boundary(*i)).unwrap_or(0);
        out.truncate(cut);
        out.push_str("..");
    }
    out
}
