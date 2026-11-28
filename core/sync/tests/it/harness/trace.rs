//! The opt-in per-node trace (notes/sync-test-harness.md, Trace): `OSIS_SYNC_TRACE=<nodes>[:<only>]`
//! prints, for each delivery to a named node, the lines of `osis_sync::trace::Trace` (what it
//! received and sent, after any lie; what the step applied; what the engine and node noted),
//! headed `n<i>`, plus each script step played. `<nodes>` is `all` or node indices joined by `,`;
//! `<only>`, tokens joined by `,`, keeps the lines holding any of them: `t<k>` stands for thing
//! k's sync IDs (as `S` and 6 hex digits), any other token is matched as text (`S1a2b3c`, `B..`,
//! `Stream`). Off (unset), the world holds no tracer and pays one branch per delivery. Lines are
//! a function of the seed: world number (`World::id`), delivery number, world time since the
//! start, node indices.

use osis_base::{BlobId, CommitId, SyncId};
use osis_proto::Msg;
use osis_sync::trace::{Only, Trace};
use osis_sync::{ConnId, Input, Out};
use std::collections::{BTreeMap, BTreeSet};

pub use osis_sync::trace::{brief, conn_name, short};

/// The variable that turns the trace on.
pub const TRACE_VAR: &str = "OSIS_SYNC_TRACE";

/// One world's trace: each traced node's `osis_sync::trace::Trace`, its lines headed `n<i>`.
#[derive(Clone)]
pub struct Tracer {
    /// Traced nodes; `None`: all.
    nodes: Option<BTreeSet<usize>>,
    only: Only,
    traces: BTreeMap<usize, Trace>,
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
        Some(Tracer { nodes, only: Only::parse(only), traces: BTreeMap::new(), lines: Vec::new() })
    }

    pub fn traces(&self, i: usize) -> bool {
        self.nodes.as_ref().is_none_or(|n| n.contains(&i))
    }

    /// Thing tokens (`t<k>`) of the filter.
    pub fn things(&self) -> Vec<usize> {
        self.only.0.iter().filter_map(|t| t.strip_prefix('t')?.parse().ok()).collect()
    }

    /// Node `i`'s lines so far, headed `n<i>`.
    fn take(&mut self, i: usize) {
        let lines = self.traces.entry(i).or_default().take();
        self.lines.extend(lines.into_iter().map(|l| format!("n{i} {l}")));
    }

    /// Node `i` is handed `input`, on a connection whose other end is `peer`'s.
    pub fn received(&mut self, i: usize, input: &Input, peer: Option<usize>) {
        self.traces.entry(i).or_default().received(input, peer.map(|p| format!("n{p}")).as_deref());
        self.take(i);
    }

    /// Node `i`'s outputs, as carried (`peer` names each connection's other end).
    pub fn sent(&mut self, i: usize, out: &[Out], peer: impl Fn(ConnId) -> Option<usize>) {
        self.traces.entry(i).or_default().sent(out, |c| peer(c).map(|p| format!("n{p}")));
        self.take(i);
    }

    /// What node `i` holds now against what it held at its last traced step.
    pub fn applied(&mut self, i: usize, entries: BTreeSet<(SyncId, BlobId)>, commits: BTreeSet<CommitId>) {
        self.traces.entry(i).or_default().applied(entries, commits);
        self.take(i);
    }

    /// Lines node `i`'s engine and node noted (`World::noted`; `None`: outside a step, `n?`).
    pub fn noted(&mut self, i: Option<usize>, lines: Vec<String>) {
        match i {
            Some(i) => {
                self.traces.entry(i).or_default().noted(lines);
                self.take(i);
            }
            None => self.lines.extend(lines.iter().map(|l| format!("n? {}", brief(l)))),
        }
    }

    /// Node `i` restarted: its connections' frames are gone.
    pub fn restarted(&mut self, i: usize) {
        self.traces.entry(i).or_default().restarted();
        self.take(i);
    }

    /// Prints the step's lines that pass the filter (`things`: the text thing tokens stand for),
    /// headed by world `w` (`World::id`: a fixture's copy counts its deliveries from 1 again),
    /// delivery `d` at `ms` since the start.
    pub fn flush(&mut self, w: u32, d: u64, ms: u64, things: &[String]) {
        let lines = std::mem::take(&mut self.lines);
        if osis_base::testenv::quiet() {
            return;
        }
        for l in lines {
            if self.only.keeps(&l, is_thing, things) {
                eprintln!("w{w} d{d} +{ms}ms {l}");
            }
        }
    }
}

/// The message kind of a frame body after Hello, as `Msg`'s variant name (`undecodable` when its
/// head does not parse, `unknown kind` for one no example shows).
pub fn kind_name(body: &[u8]) -> &'static str {
    use std::sync::OnceLock;
    static NAMES: OnceLock<BTreeMap<u64, &'static str>> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        let name = |m: &Msg| -> &'static str {
            let d = format!("{m:?}");
            let end = d.find(|c: char| !c.is_alphanumeric()).unwrap_or(d.len());
            Box::leak(d[..end].to_string().into_boxed_str()) // once per kind
        };
        osis_proto::examples::messages().iter().map(|(_, m)| (m.kind(), name(m))).collect()
    });
    match osis_proto::msg::peek_head(body) {
        Some((k, _)) => names.get(&k).copied().unwrap_or("unknown kind"),
        None => "undecodable",
    }
}

fn is_thing(t: &str) -> bool {
    t.strip_prefix('t').is_some_and(|k| k.parse::<usize>().is_ok())
}
