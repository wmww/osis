//! Phase C version skew (spec/versioning.md §2, §5): nodes of different builds and schema
//! revisions share a label. A commit of a newer format version is parked, stored and relayed, and
//! never destroyed by an old writer; a newer schema revision's fields survive an old writer's
//! writes and compaction.

use super::library::{add_tag, tags};
use super::scenarios::{ak, clock, persons, shared_group, sim};
use super::{NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use osis_core::{BlobId, CommitId, LabelId, Role, Value};
use osis_crypto::SeededRng;
use osis_node::Mutation;
use osis_proto::{Command, Entry, LabelStore};
use osis_schema::{Aspect, AspectKey, StaticSchema};
use std::collections::BTreeMap;

/// Revision 1 of the skew schema (the old build's).
pub static SKEW1: StaticSchema = StaticSchema::new(
    "skew.osis",
    r#"
schema 0x51a0000000000000000000000000005b;
revision 1;
type rec = struct { 0 a: string };
aspect /k/rec: rec;
"#,
);

/// Revision 2: a field with a default and a new aspect.
pub static SKEW2: StaticSchema = StaticSchema::new(
    "skew.osis",
    r#"
schema 0x51a0000000000000000000000000005b;
revision 2;
type rec = struct { 0 a: string, 1 b: string = "" };
aspect /k/rec: rec;
aspect /k/new: string;
"#,
);

pub const REC1: Aspect<Value> = Aspect::new("/k/rec", &SKEW1);
pub const REC2: Aspect<Value> = Aspect::new("/k/rec", &SKEW2);
pub const NEW2: Aspect<Value> = Aspect::new("/k/new", &SKEW2);

fn rec(fields: &[(i64, &str)]) -> Value {
    Value::Map(fields.iter().map(|(k, v)| (Value::Int(*k), Value::Str((*v).into()))).collect::<BTreeMap<_, _>>())
}

/// The commit plaintext of `c` held by node `n`, rewritten to format version `FORMAT_VERSION + 1`
/// (a newer build's commit; its signature is not checkable by this build anyway).
fn future_commit(sim: &mut NetSim, n: usize, c: &CommitId) -> Res<(Vec<u8>, CommitId)> {
    let bytes = sim.engine(n)?.commit_bytes(c).map_err(|e| sim.fail(e.to_string()))?.ok_or_else(|| sim.fail("no commit bytes"))?;
    let lim = osis_core::cbor::Limits { max_depth: 512, max_bytes: bytes.len() };
    let mut v = osis_core::cbor::decode(&bytes, &lim).map_err(|e| sim.fail(format!("decode: {e:?}")))?;
    if let Value::List(top) = &mut v
        && let Some(Value::List(h)) = top.first_mut()
        && let Some(ver) = h.first_mut()
    {
        *ver = Value::Int((osis_core::format::FORMAT_VERSION + 1) as i64);
    } else {
        return Err(sim.fail("commit plaintext shape"));
    }
    // the commit ID is the header's hash (spec/commits.md §1)
    let id = match &v {
        Value::List(top) => top.first().map(|h| CommitId(osis_core::hash::hash(&osis_core::cbor::encode(h)))),
        _ => None,
    };
    Ok((osis_core::cbor::encode(&v), id.ok_or_else(|| sim.fail("no header"))?))
}

/// A newer format (spec/versioning.md §1, §2): a writer of a newer build uploads a commit of
/// format version `FORMAT_VERSION + 1` (stamped and wrapped like any). Expected: every old node
/// stores it parked (pending, not read, no failure); a reader relays it to a server the writer
/// does not reach; an old writer compacting the aspect and deleting what its snapshot covers
/// leaves it at the servers (an old writer never destroys what it cannot read).
pub fn future_format(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xf5);
    let mut sim = sim("future_format", seed, NetWeights::default());
    let s0 = sim.add_server()?;
    let s1 = sim.add_server()?;
    let a = sim.add_node(&[s0], clock(&mut d))?;
    let w = sim.add_node(&[s0], clock(&mut d))?;
    let r = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s0, s1], clock(&mut d))?;
    let [pa, pw, pr, pc] = persons(&mut sim, [a, w, r, c], [s0, s0, s0, s1])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pw, Role::Write), (pr, Role::Read), (pc, Role::Read)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    // from here the writers reach s0 only and c reaches s1 only (the grants went through first)
    for n in [a, w] {
        sim.sever(Party::N(n), Party::S(s1));
    }
    sim.sever(Party::N(c), Party::S(s0));
    sim.reconnect_all();
    sim.quiet(40)?;
    add_tag(&mut sim, a, t, "old")?;
    let base = add_tag(&mut sim, w, t, "base")?;
    sim.quiet(40)?;
    // the newer build's commit, uploaded by its writer
    let (pt, fid) = future_commit(&mut sim, w, &base)?;
    let k = sim.label_keys(w, s0, &g)?;
    let mut rng = SeededRng::from_u64(sim.dice.u64());
    let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), None, Vec::new()).map_err(|e| sim.fail(e.to_string()))?;
    let (key, blob) = osis_label::frame(&prefix, &pt, &mut rng).map_err(|e| sim.fail(e.to_string()))?;
    let bid = osis_label::blob_id(&blob);
    let read = k.read.clone().ok_or_else(|| sim.fail("no read secret"))?;
    let wrap = osis_crypto::wrap(&read, &bid, &key).map_err(|e| sim.fail(e.to_string()))?;
    let write = k.keys.write.clone().ok_or_else(|| sim.fail("no write key"))?;
    let stamp = osis_label::sign_stamp(&write, &k.label, &bid, &wrap);
    let mut rg = sim.rogue(s0)?;
    sim.rogue_do(&mut rg, Command::Upload { label: k.label, entries: vec![Entry { blob, wrap, stamp }] })?;
    sim.rogue_close(&mut rg);
    sim.parked_ok.insert(fid);
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    for n in [a, w, r, c] {
        let p = sim.engine(n)?.pending();
        if !p.iter().any(|(x, _)| *x == fid) {
            return Err(sim.fail(format!("node {n} does not hold the newer commit parked: pending {p:?}")));
        }
    }
    let at = |sim: &NetSim, s: usize, l: &LabelId, b: &BlobId| sim.hub(s).is_some_and(|h| h.store().live_ids(l).unwrap_or_default().contains(b));
    if !at(&sim, s1, &k.label, &bid) {
        return Err(sim.fail("the reader did not relay the parked commit's blob to the other server"));
    }
    // an old writer compacts the aspect the newer commit wrote
    let tk = ak(&sim, &crate::workload::STORY)?;
    let acts = sim.sync(a)?.compact(&t, &tk).map_err(|e| sim.fail(format!("compact: {e}")))?;
    sim.actions(a, acts)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    for s in [s0, s1] {
        if !at(&sim, s, &k.label, &bid) {
            return Err(sim.fail(format!("an old writer destroyed the newer commit's blob at server {s}")));
        }
    }
    for n in [a, w, r, c] {
        let ts = tags(&mut sim, n, t)?;
        if !ts.contains("old") || !ts.contains("base") {
            return Err(sim.fail(format!("node {n} reads {ts:?}")));
        }
    }
    sim.finish()
}

/// A newer schema revision (spec/versioning.md §4, §5): node N writes revision 2 (a struct field
/// with a default, a new aspect); the old node reads what it knows, writes its revision-1 struct
/// and compacts. Expected: the new field and aspect survive at every node (open structs; a
/// writer never removes data its schema cannot read).
pub fn newer_schema(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x5c);
    let mut sim = sim("newer_schema", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let n = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pn] = persons(&mut sim, [a, n], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pn, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    // separate commits: compacting /k/rec then drops whole commits
    let mut m = Mutation::new();
    m.set(t, &REC2, &rec(&[(0, "n"), (1, "nb")])).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    let mut m = Mutation::new();
    m.set(t, &NEW2, &Value::Str("fresh".into())).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    sim.run(40)?;
    sim.quiet(40)?;
    let rk = osis_core::Ak::new(REC1.ak()).map_err(|e| sim.fail(e.to_string()))?;
    let nk = osis_core::Ak::new(NEW2.ak()).map_err(|e| sim.fail(e.to_string()))?;
    let got = sim.engine(a)?.get(&t, &rk).map_err(|e| sim.fail(e.to_string()))?;
    if got != Some(rec(&[(0, "n"), (1, "nb")])) {
        return Err(sim.fail(format!("the old node reads {got:?} of the newer struct")));
    }
    // the old node writes its revision of the struct, then compacts it
    let mut m = Mutation::new();
    m.set(t, &REC1, &rec(&[(0, "old")])).map_err(|e| sim.fail(format!("old write: {e}")))?;
    sim.commit(a, m)?;
    sim.run(40)?;
    sim.quiet(40)?;
    let acts = sim.sync(a)?.compact(&t, &rk).map_err(|e| sim.fail(format!("compact: {e}")))?;
    sim.actions(a, acts)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    for x in [a, n] {
        let r = sim.engine(x)?.get(&t, &rk).map_err(|e| sim.fail(e.to_string()))?;
        if r != Some(rec(&[(0, "old"), (1, "nb")])) {
            return Err(sim.fail(format!("node {x} reads {r:?}: the old writer destroyed the newer field")));
        }
        let v = sim.engine(x)?.get(&t, &nk).map_err(|e| sim.fail(e.to_string()))?;
        if v != Some(Value::Str("fresh".into())) {
            return Err(sim.fail(format!("node {x} reads {v:?} of the newer aspect")));
        }
    }
    sim.finish()
}
