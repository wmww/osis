//! One node's trace (notes/sync-test-harness.md, Trace), the lines both the
//! harness's `OSIS_SYNC_TRACE` and, in debug builds, a node's own trace (`Node::trace`, the
//! CLI's `OSIS_NODE_TRACE`) print: for each step, what the node received and sent (each message
//! decoded; Hello, up, closed, dial, close), what the step applied (store entries and engine
//! commits gained or lost against its last traced step), and what the engine and node noted to
//! `osis_base::trace` (a body's verdict moving, lost access firing, a transaction refused, a
//! record-blob judgement changing). Lines carry no node name: the caller heads them.

use crate::{ConnId, Input, Out};
use osis_base::{BlobId, CommitId, SyncId};
use osis_proto::{FrameDecoder, Msg};
use std::collections::{BTreeMap, BTreeSet};

/// A request not answered yet, per (its conn, whether this node sent it, its id).
type Asking = (ConnId, bool, osis_proto::Id);

/// One node's trace: its connections' frame decoders, what it held at its last traced step,
/// and the lines of the step being traced.
#[derive(Clone, Default)]
pub struct Trace {
    /// Frames per (conn, sent), and whether the Hello went by.
    frames: BTreeMap<(ConnId, bool), (FrameDecoder, bool)>,
    entries: BTreeSet<(SyncId, BlobId)>,
    commits: BTreeSet<CommitId>,
    /// Offers and Losts not answered yet: the request's kind and items, for its answer's line
    /// (`paired`).
    asked: BTreeMap<Asking, (&'static str, Vec<String>)>,
    /// Per sync ID's text, the last record-blob judgement kept (`noted`).
    records: BTreeMap<String, String>,
    lines: Vec<String>,
}

impl Trace {
    /// The node is handed `input`; `peer` names its connection's other end (`n2`, a key's hex).
    pub fn received(&mut self, input: &Input, peer: Option<&str>) {
        let from = peer.map_or(String::new(), |p| format!(" {p}"));
        let line = match input {
            Input::Bytes { conn, bytes } => {
                for m in self.decode(*conn, false, bytes) {
                    self.lines.push(format!("<-{from} {}: {m}", conn_name(*conn)));
                }
                return;
            }
            Input::Up { conn, rank, dialed, .. } => format!("up{from} {} rank {rank}{}", conn_name(*conn), if *dialed { " dialed" } else { "" }),
            Input::Taken { .. } => return,
            Input::Closed { conn } => format!("closed{from} {}", conn_name(*conn)),
            Input::Down { conn, .. } => format!("down {}", conn_name(*conn)),
            Input::Tick => "tick".to_string(),
            Input::Wrote => "wrote".to_string(),
            Input::Discovered { addr } => format!("discovered {}", hex(&addr.key)),
        };
        self.lines.push(line);
    }

    /// The node's outputs, as carried (`peer` names each connection's other end).
    pub fn sent(&mut self, out: &[Out], peer: impl Fn(ConnId) -> Option<String>) {
        for o in out {
            match o {
                Out::Send(conn, bytes) => {
                    let to = peer(*conn).map_or(String::new(), |p| format!(" {p}"));
                    for m in self.decode(*conn, true, bytes) {
                        self.lines.push(format!("->{to} {}: {m}", conn_name(*conn)));
                    }
                }
                Out::Dial(conn, to) => self.lines.push(format!("dial {} {}", conn_name(*conn), hex(&to.key))),
                Out::Close(conn) => {
                    self.frames.retain(|(c, _), _| c != conn);
                    self.asked.retain(|(c, ..), _| c != conn);
                    self.lines.push(format!("close {}", conn_name(*conn)));
                }
                Out::Read(conn, on) => self.lines.push(format!("read {} {on}", conn_name(*conn))),
                Out::Wake(_) => {}
            }
        }
    }

    /// What the node holds now against what it held at its last traced step.
    pub fn applied(&mut self, entries: BTreeSet<(SyncId, BlobId)>, commits: BTreeSet<CommitId>) {
        for (s, b) in entries.difference(&self.entries) {
            self.lines.push(format!("+entry {} {}", brief(&format!("{s:?}")), brief(&format!("{b:?}"))));
        }
        for (s, b) in self.entries.difference(&entries) {
            self.lines.push(format!("-entry {} {}", brief(&format!("{s:?}")), brief(&format!("{b:?}"))));
        }
        for c in commits.difference(&self.commits) {
            self.lines.push(format!("+commit {}", brief(&format!("{c:?}"))));
        }
        for c in self.commits.difference(&commits) {
            self.lines.push(format!("-commit {}", brief(&format!("{c:?}"))));
        }
        (self.entries, self.commits) = (entries, commits);
    }

    /// Lines the node's engine and node noted (`osis_base::trace`). A record-blob judgement
    /// (`record blobs S..: ..`, noted each time it runs) is kept only where it differs from the
    /// last one under that S.
    pub fn noted(&mut self, lines: Vec<String>) {
        for l in lines {
            let l = brief(&l);
            if let Some((s, _)) = l.strip_prefix("record blobs ").and_then(|r| r.split_once(':')) {
                if self.records.get(s) == Some(&l) {
                    continue;
                }
                self.records.insert(s.to_string(), l.clone());
            }
            self.lines.push(l);
        }
    }

    /// The node restarted: its connections' frames are gone.
    pub fn restarted(&mut self) {
        self.frames.clear();
        self.asked.clear();
        self.records.clear();
        self.lines.push("restarted".to_string());
    }

    /// The step's lines, taken.
    pub fn take(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// The messages of `bytes` on `conn` (`sent`: the node's own), the Hello named only.
    fn decode(&mut self, conn: ConnId, sent: bool, bytes: &[u8]) -> Vec<String> {
        let (f, hello) = self.frames.entry((conn, sent)).or_insert_with(|| (FrameDecoder::default(), false));
        f.push(bytes);
        let mut bodies = Vec::new();
        while let Ok(Some(body)) = f.next_frame() {
            bodies.push((!std::mem::replace(hello, true), body));
        }
        bodies
            .into_iter()
            .map(|(is_hello, body)| {
                if is_hello {
                    return "Hello".to_string();
                }
                match Msg::decode(&body) {
                    Ok(m) => self.paired(conn, sent, &m).unwrap_or_else(|| brief(&format!("{m:?}"))),
                    Err(e) => format!("undecodable ({e:?}, {} bytes)", body.len()),
                }
            })
            .collect()
    }

    /// An Offer or Lost is kept for its answer; a Shared or Error answering one is printed with
    /// it, each request item beside its answer (`<item> => <answer>`), so the answer's line holds
    /// what the request named (a filter that keeps one keeps the other). `None`: any other
    /// message, printed as it is.
    fn paired(&mut self, conn: ConnId, sent: bool, m: &Msg) -> Option<String> {
        match m {
            Msg::Offer { id, items } => {
                self.asked.insert((conn, sent, *id), ("Offer", items.iter().map(|x| brief(&format!("{x:?}"))).collect()));
                None
            }
            Msg::Lost { id, items } => {
                self.asked.insert((conn, sent, *id), ("Lost", items.iter().map(|x| brief(&format!("{x:?}"))).collect()));
                None
            }
            // an answer goes the other way from its request
            Msg::Shared { id, items } => {
                let (kind, asked) = self.asked.remove(&(conn, !sent, *id))?;
                let n = asked.len().max(items.len());
                let pairs: Vec<String> = (0..n).map(|k| format!("{} => {}", asked.get(k).map_or("(none)", String::as_str), items.get(k).map_or("(none)".to_string(), |x| brief(&format!("{x:?}"))))).collect();
                Some(format!("Shared {{ id: {id} }} answers {kind}: [{}]", pairs.join("; ")))
            }
            Msg::Error { id, .. } => {
                let (kind, asked) = self.asked.remove(&(conn, !sent, *id))?;
                Some(format!("{} answers {kind}: [{}]", brief(&format!("{m:?}")), asked.join(", ")))
            }
            _ => None,
        }
    }
}

/// A trace's filter: `<only>` tokens joined by `,` (none: every line). A line is kept when it
/// holds any token as text, or any of `things` (the texts a caller's own tokens stand for).
#[derive(Clone, Debug, Default)]
pub struct Only(pub Vec<String>);

impl Only {
    pub fn parse(spec: &str) -> Only {
        Only(spec.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
    }

    /// Whether `line` is printed; `own(token)`: a caller's token, matched only through `things`.
    pub fn keeps(&self, line: &str, own: impl Fn(&str) -> bool, things: &[String]) -> bool {
        self.0.is_empty() || self.0.iter().filter(|t| !own(t)).chain(things).any(|t| line.contains(t.as_str()))
    }
}

/// A connection end as a trace prints it: `c<n>` dialed, `a<n>` accepted.
pub fn conn_name(conn: ConnId) -> String {
    if conn.accepted() { format!("a{}", conn.0 & !ConnId::ACCEPTED) } else { format!("c{}", conn.0) }
}

/// A sync ID as a trace prints it.
pub fn short(s: &SyncId) -> String {
    brief(&format!("{s:?}"))
}

/// A key's first three bytes as hex: a peer or dialed node as a trace names it.
pub fn hex(b: &[u8]) -> String {
    b.iter().take(3).map(|x| format!("{x:02x}")).collect()
}

/// A Debug string made compact: `SyncId(1a2b3c..)` as `S1a2b3c`, `BlobId` as `B..`, `CommitId` as
/// `C..`; a list of more than 8 numbers (bytes) as `[N b]`. Never cut: what makes a line long
/// (a growing list) is what a trace is read for.
pub fn brief(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
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
    out
}

/// A node's own trace (`Node::trace`): its lines printed to stderr as each step ends, headed
/// `d<step> +<ms>ms` (ms on the node's monotonic clock since the trace began), peers named by
/// their keys' first bytes.
#[cfg(debug_assertions)]
pub(crate) struct Own {
    pub trace: Trace,
    pub only: Only,
    /// Each up connection's peer.
    pub peers: BTreeMap<ConnId, String>,
    pub steps: u64,
    pub since: osis_base::Mono,
    pub restarts: u64,
    pub sink: Box<dyn FnMut(&str) + Send>,
}

#[cfg(debug_assertions)]
impl Own {
    /// What a step took and gave, and what it applied; `input` none for outputs made outside a
    /// step.
    pub fn stepped(&mut self, input: Option<&Input>, out: &[Out], held: impl FnOnce() -> (BTreeSet<(SyncId, BlobId)>, BTreeSet<CommitId>), now: osis_base::Mono, restarts: u64) {
        // engine and node lines noted on this thread outside a step come first
        let before = osis_base::trace::take();
        self.trace.noted(before);
        if let Some(i) = input {
            if let Input::Up { conn, peer, .. } = i {
                self.peers.insert(*conn, hex(&peer.0));
            }
            let peer = match i {
                Input::Up { conn, .. } | Input::Bytes { conn, .. } | Input::Closed { conn } => self.peers.get(conn).cloned(),
                _ => None,
            };
            self.trace.received(i, peer.as_deref());
            if let Input::Closed { conn } = i {
                self.peers.remove(conn);
            }
        }
        let peers = &self.peers;
        self.trace.sent(out, |c| peers.get(&c).cloned());
        if restarts != self.restarts {
            self.restarts = restarts;
            self.trace.restarted();
        }
        // a step's change (outputs made outside one, the client port's, change nothing held)
        if input.is_some() {
            let (entries, commits) = held();
            self.trace.applied(entries, commits);
        }
        self.steps += 1;
        let ms = now.0.saturating_sub(self.since.0);
        for l in self.trace.take() {
            if self.only.keeps(&l, |_| false, &[]) {
                (self.sink)(&format!("d{} +{ms}ms {l}", self.steps));
            }
        }
    }
}
