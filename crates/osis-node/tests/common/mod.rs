#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, dead_code)]
//! Shared test helpers: a test schema with one aspect per encoding, grants, delivery.

use osis_commit::Kind;
use osis_core::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::{LocalPeer, Package};
use osis_node::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{Aspect, Codec, StaticSchema};

pub const T0: WallMs = WallMs(1_700_000_000_000);

pub static TEST: StaticSchema = StaticSchema::new(
    "test.osis",
    r#"
schema 0x0123456789abcdef0123456789abcdef;
revision 1;
type item = struct { 0 name: string, 1 n: int };
type shape = enum { 0 dot, 1 circle(int) };
aspect /t/reg: string;
aspect /t/count: counter<int>;
aspect /t/hi: max<int>;
aspect /t/lo: min<int>;
aspect /t/rec: item;
aspect /t/shape: shape;
aspect /t/tags: set<string>;
aspect /t/map: map<string, item>;
aspect /t/big: map<string, string>;
aspect /t/gone: string [by: writer, keep_at_most: 0s];
aspect /t/brief: string [expires: 1h];
aspect /t/kept: string [by: writer, keep_at_least: 1d];
aspect /t/list: list<string>;
aspect /t/text: text;
aspect /t/blob: blob;
"#,
);

pub const REG: Aspect<Value> = Aspect::new("/t/reg", &TEST);
pub const COUNT: Aspect<Value> = Aspect::new("/t/count", &TEST);
pub const HI: Aspect<Value> = Aspect::new("/t/hi", &TEST);
pub const LO: Aspect<Value> = Aspect::new("/t/lo", &TEST);
pub const REC: Aspect<Value> = Aspect::new("/t/rec", &TEST);
pub const SHAPE: Aspect<Value> = Aspect::new("/t/shape", &TEST);
pub const TAGS: Aspect<Value> = Aspect::new("/t/tags", &TEST);
pub const MAP: Aspect<Value> = Aspect::new("/t/map", &TEST);
pub const BIG: Aspect<Value> = Aspect::new("/t/big", &TEST);
pub const GONE: Aspect<Value> = Aspect::new("/t/gone", &TEST);
pub const BRIEF: Aspect<Value> = Aspect::new("/t/brief", &TEST);
pub const KEPT: Aspect<Value> = Aspect::new("/t/kept", &TEST);
pub const LIST: Aspect<Value> = Aspect::new("/t/list", &TEST);
pub const TEXT: Aspect<Value> = Aspect::new("/t/text", &TEST);
pub const BLOB: Aspect<Value> = Aspect::new("/t/blob", &TEST);

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

pub fn s(x: &str) -> Value {
    Value::Str(x.into())
}

pub fn item(name: &str, n: i64) -> Value {
    Value::Map([(Value::Int(0), s(name)), (Value::Int(1), Value::Int(n))].into_iter().collect())
}

pub fn net(n: usize, seed: u64) -> LocalPeer {
    LocalPeer::new(n, seed, T0).unwrap()
}

/// A new thing owned by peer `i`'s node.
pub fn new_thing(lp: &mut LocalPeer, i: usize) -> Tid {
    let p = lp.peer(i).unwrap();
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("new")).unwrap();
    p.commit(m).unwrap();
    t
}

pub fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None }
}

/// Peer `i` writes `member`'s edge on `thing` (`None` removes it), with an optional frontier.
pub fn set_edge(e: &mut Engine, thing: Tid, member: Tid, edge: Option<ct::Edge>, frontier: Option<Value>) -> CommitId {
    let mut m = Mutation::new();
    let op = match edge {
        Some(x) => Op::Set(x.to_value()),
        None => Op::Remove(Value::Tid(member)),
    };
    let path = match op {
        Op::Set(_) => vec![PathSeg::Key(Value::Tid(member))],
        _ => Vec::new(),
    };
    m.op(thing, &ct::MEMBERS, PathOp { path, op }).unwrap();
    if let Some(f) = frontier {
        m.frontier(f);
    }
    e.commit(m).unwrap().unwrap()
}

/// Delivers every commit of `from` to `to`.
pub fn sync(lp: &mut LocalPeer, from: usize, to: usize) {
    lp.sync(from, to).unwrap();
}

pub fn packages(lp: &mut LocalPeer, from: usize) -> Vec<Package> {
    lp.packages(from).unwrap()
}

pub fn is_membership(e: &Engine, id: &CommitId) -> bool {
    e.header(id).is_some_and(|h| h.kind == Kind::Membership)
}

/// Canonical bytes of every aspect state of `tids` (convergence check).
pub fn states(e: &mut Engine, tids: &[Tid]) -> Vec<(Tid, Ak, Option<Value>)> {
    let mut out = Vec::new();
    for (t, a) in e.all_aspects().unwrap() {
        if tids.contains(&t) {
            out.push((t, a.clone(), e.get(&t, &a).unwrap()));
        }
    }
    out.sort_by(|x, y| (x.0, x.1.as_str()).cmp(&(y.0, y.1.as_str())));
    out
}
