//! Phase B scenarios: sync engines and blind servers under message faults, partitions,
//! crashes and data loss. Each is a function of the seed; `crate::replay` reruns any. Setup runs
//! calm (no faults) and settles with `quiet`; `run` is the faulty random schedule; every
//! scenario ends with `run_until_quiescent` (the invariants of `check`).

use super::{LinkFaults, NetConfig, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{ClockSpec, Report, Res};
use crate::workload;
use osis_commit::PurgeItem;
use osis_core::format::MEMBERSHIP_KEEP_MS;
use osis_core::{Ak, Role, Tid, Value};
use osis_node::Mutation;
use osis_node::flows::PreSync;
use osis_node::sync::Event;
use osis_schema::AspectKey;

const DAY_MS: u64 = 86_400_000;

fn lossy() -> LinkFaults {
    LinkFaults { cut_pct: 2, dup_pct: 1, max_delay_ms: 3_000, reorder: true }
}

fn clock(d: &mut Dice) -> ClockSpec {
    ClockSpec { skew_ms: d.range_i64(-20_000, 20_000), drift_ppm: d.range_i64(-100, 100) }
}

fn sim(name: &str, seed: u64, weights: NetWeights) -> NetSim {
    NetSim::new(name, seed, NetConfig { faults: lossy(), weights, ..NetConfig::default() })
}

fn ak(sim: &NetSim, a: &osis_schema::Aspect<Value>) -> Res<Ak> {
    Ak::new(a.ak()).map_err(|e| sim.fail(e.to_string()))
}

/// Newest current read epoch of `g` whose secret node `n` holds.
fn newest_read(sim: &mut NetSim, n: usize, g: &Tid) -> Res<Option<u64>> {
    Ok(sim.engine(n)?.epochs(g).and_then(|e| e.read.newest_held().map(|x| x.0.n())))
}

/// Persons on nodes `ns` (homes at `homes[i]`), each introduced to the first: the first node's
/// person and the others'.
fn persons<const N: usize>(sim: &mut NetSim, ns: [usize; N], homes: [usize; N]) -> Res<[Tid; N]> {
    let mut ps = Vec::new();
    for (n, h) in ns.iter().zip(homes) {
        ps.push(sim.person(*n, &[h])?.person);
    }
    if let Some((first, rest)) = ns.split_first() {
        for n in rest {
            sim.introduce(*n, *first)?;
        }
    }
    sim.quiet(40)?;
    ps.try_into().map_err(|_| sim.fail("persons"))
}

/// A group of node `a`'s person at `servers`, granted to each (person, role) in turn.
fn shared_group(sim: &mut NetSim, a: usize, pa: Tid, servers: &[usize], grants: &[(Tid, Role)]) -> Res<Tid> {
    let g = sim.group(a, pa, servers)?;
    for (p, r) in grants {
        sim.grant(a, g, *p, *r)?;
        sim.quiet(40)?;
    }
    Ok(g)
}

/// A purge of `c`'s `/s/gone` delta on `t` by node `n` (spec/commits.md §5), recorded for the
/// purge invariant.
fn purge(sim: &mut NetSim, n: usize, c: osis_core::CommitId, t: Tid) -> Res<()> {
    sim.observe()?;
    let gone = ak(sim, &workload::GONE)?;
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &workload::GONE).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    sim.purged.push((c, t, gone));
    Ok(())
}

/// Node `n` writes `/s/gone` on `t`.
fn write_gone(sim: &mut NetSim, n: usize, t: Tid, v: &str) -> Res<osis_core::CommitId> {
    let mut m = Mutation::new();
    m.set(t, &workload::GONE, &Value::Str(v.into())).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))
}

/// Two devices of one person through one blind server (spec/sync.md §2, §6): the person's
/// home label, the second device paired; both write items of the person's group under a lossy
/// network with crashes mid-write.
pub fn two_devices_server(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xb2);
    let mut sim = sim("two_devices_server", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_server()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d0, &[s])?.person;
    sim.pair(d0, d1, p)?;
    sim.item(d0, p)?;
    sim.item(d0, p)?;
    sim.run(200)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Three persons share a group through two replicating servers (spec/sync.md §5 replication,
/// §6): A (admin, reaches both), B (writer, s0 only), C (reader, s1 only); grants by inbox;
/// server crashes mid-write, partitions.
pub fn three_persons_two_servers(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x3b);
    let w = NetWeights { server_crash: 1, server_restart: 2, partition: 1, heal: 2, ..NetWeights::default() };
    let mut sim = sim("three_persons_two_servers", seed, w);
    let s0 = sim.add_server()?;
    let s1 = sim.add_server()?;
    sim.replicate(s0, s1)?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let b = sim.add_node(&[s0], clock(&mut d))?;
    let c = sim.add_node(&[s1], clock(&mut d))?;
    sim.sever(Party::N(b), Party::S(s1));
    sim.sever(Party::N(c), Party::S(s0));
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s0, s0, s1])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Read)])?;
    sim.item(a, g)?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(200)?;
    sim.run_until_quiescent(60)?;
    sim.finish()
}

/// A removed writer's bodies deleted by token (spec/sync.md §5 deletion by token; spec/commits.md
/// §5): W writes a writer-purgeable aspect, the admin removes W, then a remaining writer (no
/// delete key) purges W's body while the admin is away; it is gone from the server and from
/// every honest node.
pub fn removed_writer(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7e);
    let mut sim = sim("removed_writer", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let w = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pw] = persons(&mut sim, [a, b, w], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pw, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(50)?;
    sim.quiet(40)?;
    let cw = write_gone(&mut sim, w, t, "by w")?;
    sim.run(30)?;
    sim.quiet(40)?;
    sim.remove(a, g, pw)?;
    sim.excused.insert(w);
    sim.run(30)?;
    sim.quiet(40)?;
    if sim.engine(b)?.header(&cw).is_none() {
        return Err(sim.fail("B never received W's body"));
    }
    // the admin is away: B purges W's body and deletes it by token
    sim.node_down(a)?;
    purge(&mut sim, b, cw, t)?;
    sim.run(30)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b] {
        if sim.engine(n)?.roster(&g).contains_key(&pw) {
            return Err(sim.fail(format!("node {n} still lists the removed writer")));
        }
    }
    sim.finish()
}

/// Compaction, then deletion (spec/sync.md §7): two writers compact aspects while writing;
/// covered bodies are deleted at the server once the snapshot is there; then a purge; no
/// ping-pong.
pub fn compaction(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc0);
    let mut sim = sim("compaction", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(120)?;
    sim.quiet(40)?;
    let deleted0 = deletions(&sim, s);
    for (n, a_) in [(a, &workload::REG), (b, &workload::TAGS), (a, &workload::MAP)] {
        let k = ak(&sim, a_)?;
        let acts = sim.sync(n)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
        sim.actions(n, acts)?;
        sim.run(30)?;
    }
    sim.run_until_quiescent(40)?;
    if deletions(&sim, s) == deleted0 {
        return Err(sim.fail("compaction deleted nothing at the server"));
    }
    let c = write_gone(&mut sim, a, t, "later")?;
    sim.quiet(40)?;
    purge(&mut sim, b, c, t)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Deleted records in the logs of server `s`.
fn deletions(sim: &NetSim, s: usize) -> usize {
    use osis_proto::LabelStore;
    let Some(h) = sim.hub(s) else { return 0 };
    let mut k = 0;
    for l in h.store().labels_after(None, 4096).unwrap_or_default() {
        let recs = h.store().log_after(&l, 0, 1 << 20).ok().flatten().unwrap_or_default();
        k += recs.iter().filter(|(_, r)| matches!(r, osis_proto::LogRecord::Deleted(_))).count();
    }
    k
}

/// A reader relays (spec/sync.md §5, §6): two servers that do not replicate; the writer reaches
/// only s0, a reader both, a second reader only s1; the second reader reads the writer's content
/// carried by the first. The readers open the label while the admin registers the steps of the
/// grants' rotations (an open answered with the old head follows the new one).
pub fn reader_relays(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x2e);
    let mut sim = sim("reader_relays", seed, NetWeights::default());
    let s0 = sim.add_server()?;
    let s1 = sim.add_server()?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let r = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s1], clock(&mut d))?;
    sim.sever(Party::N(c), Party::S(s0));
    let [pa, pr, pc] = persons(&mut sim, [a, r, c], [s0, s0, s1])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pr, Role::Read), (pc, Role::Read)])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    // from now on the writer reaches s0 only
    sim.sever(Party::N(a), Party::S(s1));
    sim.run(120)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A stranded device re-sealed (spec/permissions.md §3, §4; notes/sync.md Limits): one device of
/// a person is off while two others are removed (the person rotates twice, the home label steps
/// twice) and stays off past `MEMBERSHIP_KEEP`, so the server dropped the claim set it needs; it
/// cannot read the new epoch; re-paired over a direct connection it does.
pub fn stranded_reseal(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x5d);
    let mut sim = sim("stranded_reseal", seed, NetWeights::default());
    let s = sim.add_server()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let d2 = sim.add_node(&[s], clock(&mut d))?;
    let d3 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d0, &[s])?.person;
    for x in [d1, d2, d3] {
        sim.pair(d0, x, p)?;
    }
    sim.item(d0, p)?;
    sim.run(60)?;
    sim.quiet(40)?;
    let before = newest_read(&mut sim, d1, &p)?;
    sim.node_down(d1)?;
    for x in [d2, d3] {
        let t = sim.tid(x)?;
        sim.lose_disk(x)?;
        sim.remove(d0, p, t)?;
        sim.settle()?;
    }
    let after = newest_read(&mut sim, d0, &p)?;
    if after == before {
        return Err(sim.fail("the removals did not rotate the person"));
    }
    sim.advance(MEMBERSHIP_KEEP_MS + 2 * DAY_MS)?;
    sim.settle()?;
    sim.restart_node(d1)?;
    for _ in 0..4 {
        sim.advance(61_000)?;
        sim.settle()?;
    }
    if newest_read(&mut sim, d1, &p)? == after {
        return Err(sim.fail("the device past MEMBERSHIP_KEEP was not stranded (it read the new epoch by claim)"));
    }
    // re-paired: a re-seal over the direct connection
    sim.pair(d0, d1, p)?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    if newest_read(&mut sim, d1, &p)? != newest_read(&mut sim, d0, &p)? {
        return Err(sim.fail("the re-sealed device does not hold the person's newest epoch"));
    }
    sim.finish()
}

/// A server loses its data (spec/sync.md §6: a writer uploads every must-hold body the label
/// lacks): writers re-register the labels and re-upload; the quiescent check finds every
/// must-hold body back.
pub fn server_loses_data(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x10);
    let mut sim = sim("server_loses_data", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(120)?;
    sim.wipe_server(s)?;
    sim.run(120)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A node offline across rotations walks the steps (spec/sync.md §5 Open, Claim): a reader is
/// off while the admin removes a reader and then a writer (two rotations, two steps) and keeps
/// writing; back online it walks by its stale sync key and reads; the removed members hold no
/// later epoch.
pub fn offline_rotation(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x0f);
    let mut sim = sim("offline_rotation", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let e = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc, pe] = persons(&mut sim, [a, b, c, e], [s, s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Read), (pc, Role::Read), (pe, Role::Write)])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(30)?;
    sim.quiet(40)?;
    sim.node_down(c)?;
    sim.remove(a, g, pb)?;
    sim.excused.insert(b);
    sim.run(30)?;
    sim.settle()?;
    let mid = newest_read(&mut sim, a, &g)?;
    sim.remove(a, g, pe)?;
    sim.excused.insert(e);
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    let now = newest_read(&mut sim, a, &g)?;
    if newest_read(&mut sim, c, &g)? != now {
        return Err(sim.fail("the reader back online does not hold the newest epoch"));
    }
    let x = newest_read(&mut sim, b, &g)?;
    if x.is_some_and(|x| Some(x) >= mid) {
        return Err(sim.fail(format!("a removed reader holds epoch {x:?}, the first after its removal is {mid:?}")));
    }
    if newest_read(&mut sim, e, &g)?.is_some_and(|x| Some(x) >= now) {
        return Err(sim.fail("a removed writer holds an epoch after its removal"));
    }
    sim.finish()
}

/// Disk loss and recovery from the card (spec/permissions.md §9): one of a person's two devices
/// loses its disk; a fresh device holding the card follows the home label, recovers (grants
/// itself admin, removes the lost device with the person's rotation) and converges with the
/// remaining device. Fails: issues/flows-recovered-device-writes.md.
pub fn disk_loss(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xd1);
    let mut sim = sim("disk_loss", seed, NetWeights::default());
    let s = sim.add_server()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let person = sim.person(d0, &[s])?;
    let p = person.person;
    sim.pair(d0, d1, p)?;
    sim.item(d0, p)?;
    sim.item(d1, p)?;
    sim.run(80)?;
    sim.lose_disk(d0)?;
    sim.run(40)?;
    sim.quiet(40)?;
    let fresh = sim.add_node(&[s], clock(&mut d))?;
    let card = person.card.clone();
    let r = sim.engine(fresh)?.hold_key_actor(card.seed.clone());
    r.map_err(|e| sim.fail(format!("hold_key_actor: {e}")))?;
    let acts = sim.sync(fresh)?.follow(card.person, card.home_label, card.servers.clone());
    sim.actions(fresh, acts)?;
    sim.quiet(40)?;
    let lost = sim.tid(d0)?;
    let r = sim.engine(fresh)?.recover(&card, &[lost], PreSync::Synced);
    let done = r.map_err(|e| sim.fail(format!("recover: {e}")))?;
    sim.carry(fresh, done)?;
    sim.feed(fresh, Event::Local)?;
    sim.person_of.insert(fresh, p);
    sim.quiet(40)?;
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    let ft = sim.tid(fresh)?;
    for n in [d1, fresh] {
        let roster = sim.engine(n)?.roster(&p);
        if roster.contains_key(&lost) || !roster.contains_key(&ft) {
            return Err(sim.fail(format!("node {n}: the person's roster after recovery: {:?}", roster.keys().collect::<Vec<_>>())));
        }
    }
    sim.finish()
}


/// A grant whose inbox deposit is lost (spec/sync.md §3, §5): the admin's device crashes right
/// after granting, before the deposit reached the server; after restart nothing re-sends it.
/// Fails: issues/sync-inbox-delivery.md (the grantee never learns of the grant).
pub fn grant_lost_on_crash(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x9c);
    let mut sim = sim("grant_lost_on_crash", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = sim.group(a, pa, &[s])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    sim.grant(a, g, pb, Role::Read)?;
    sim.node_down(a)?;
    sim.restart_node(a)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}
