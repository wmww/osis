//! Phase B scenarios: sync engines and blind servers under message faults, partitions,
//! crashes and data loss. Each is a function of the seed; `crate::replay` reruns any.

use super::{LinkFaults, NetConfig, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{ClockSpec, Report, Res};
use crate::workload;
use osis_commit::PurgeItem;
use osis_core::format::MEMBERSHIP_KEEP_MS;

const DAY_MS: u64 = 86_400_000;
use osis_core::{Ak, Role, Tid, Value};
use osis_node::Mutation;
use osis_node::flows::PreSync;
use osis_node::sync::Event;
use osis_schema::AspectKey;

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

/// Newest read epoch number node `n` holds of `g`.
fn newest_read(sim: &mut NetSim, n: usize, g: &Tid) -> Res<Option<u64>> {
    Ok(sim.engine(n)?.epochs(g).and_then(|e| e.read.newest().map(|x| x.n())))
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
    sim.run(300)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Three persons share a group through two replicating servers (spec/sync.md §5 replication,
/// §6): A (admin, reaches both), B (writer, reaches s0 only), C (reader, s1 only); grants by
/// inbox; server crashes mid-write, partitions.
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
    let pa = sim.person(a, &[s0])?.person;
    let pb = sim.person(b, &[s0])?.person;
    let pc = sim.person(c, &[s1])?.person;
    sim.introduce(b, a)?;
    sim.introduce(c, a)?;
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s0, s1])?;
    sim.grant(a, g, pb, Role::Write)?;
    sim.run_until_quiescent(40)?;
    sim.grant(a, g, pc, Role::Read)?;
    sim.run_until_quiescent(40)?;
    sim.item(a, g)?;
    sim.item(a, g)?;
    sim.run(300)?;
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
    let pa = sim.person(a, &[s])?.person;
    let pb = sim.person(b, &[s])?.person;
    let pw = sim.person(w, &[s])?.person;
    sim.introduce(b, a)?;
    sim.introduce(w, a)?;
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s])?;
    sim.grant(a, g, pb, Role::Write)?;
    sim.run_until_quiescent(40)?;
    sim.grant(a, g, pw, Role::Write)?;
    sim.run_until_quiescent(40)?;
    let t = sim.item(a, g)?;
    sim.run(100)?;
    sim.run_until_quiescent(40)?;
    let mut m = Mutation::new();
    m.set(t, &workload::GONE, &Value::Str("by w".into())).map_err(|e| sim.fail(e.to_string()))?;
    let cw = sim.commit(w, m)?.ok_or_else(|| sim.fail("W wrote nothing"))?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    sim.remove(a, g, pw)?;
    sim.excused.insert(w);
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    if sim.engine(b)?.header(&cw).is_none() {
        return Err(sim.fail("B never received W's body"));
    }
    // the admin is away: B purges W's body and deletes it by token
    sim.observe()?;
    sim.node_down(a)?;
    let gone = ak(&sim, &workload::GONE)?;
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: cw, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &workload::GONE).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(b, m)?;
    sim.purged.push((cw, t, gone));
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b] {
        if sim.engine(n)?.roster(&g).contains_key(&pw) {
            return Err(sim.fail(format!("node {n} still lists the removed writer")));
        }
    }
    sim.finish()
}

/// Compaction, then deletion (spec/sync.md §7): writers compact an aspect while writing; covered
/// bodies are deleted at the server once the snapshot is there; a later purge of a snapshot-era
/// body; no ping-pong.
pub fn compaction(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc0);
    let mut sim = sim("compaction", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let pa = sim.person(a, &[s])?.person;
    let pb = sim.person(b, &[s])?.person;
    sim.introduce(b, a)?;
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s])?;
    sim.grant(a, g, pb, Role::Write)?;
    sim.run_until_quiescent(40)?;
    let t = sim.item(a, g)?;
    sim.run(150)?;
    sim.run_until_quiescent(40)?;
    let deleted0 = deletions(&sim, s);
    for (n, a_) in [(a, &workload::REG), (b, &workload::TAGS), (a, &workload::MAP)] {
        let k = ak(&sim, a_)?;
        let acts = sim.sync(n)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
        sim.actions(n, acts)?;
        sim.run(40)?;
    }
    sim.run_until_quiescent(40)?;
    if deletions(&sim, s) == deleted0 {
        return Err(sim.fail("compaction deleted nothing at the server"));
    }
    let mut m = Mutation::new();
    m.set(t, &workload::GONE, &Value::Str("later".into())).map_err(|e| sim.fail(e.to_string()))?;
    let c = sim.commit(a, m)?.ok_or_else(|| sim.fail("no commit"))?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    sim.observe()?;
    let gone = ak(&sim, &workload::GONE)?;
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &workload::GONE).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(b, m)?;
    sim.purged.push((c, t, gone));
    sim.run(60)?;
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
/// carried by the first.
pub fn reader_relays(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x2e);
    let mut sim = sim("reader_relays", seed, NetWeights::default());
    let s0 = sim.add_server()?;
    let s1 = sim.add_server()?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let r = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s1], clock(&mut d))?;
    sim.sever(Party::N(c), Party::S(s0));
    let pa = sim.person(a, &[s0])?.person;
    let pr = sim.person(r, &[s0])?.person;
    let pc = sim.person(c, &[s1])?.person;
    sim.introduce(r, a)?;
    sim.introduce(c, a)?;
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s0, s1])?;
    sim.grant(a, g, pr, Role::Read)?;
    sim.grant(a, g, pc, Role::Read)?;
    sim.run_until_quiescent(40)?;
    sim.item(a, g)?;
    sim.run_until_quiescent(40)?;
    // from now on the writer reaches s0 only
    sim.sever(Party::N(a), Party::S(s1));
    sim.run(200)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A stranded device re-sealed (spec/permissions.md §3, §4; notes/sync.md Limits): one device of
/// a person is off while another device is removed (the person rotates, the home label steps)
/// and stays off past `MEMBERSHIP_KEEP`, so the server dropped the claim set it needs; it places
/// a stranded heartbeat; re-paired over a direct connection it reads again.
pub fn stranded_reseal(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x5d);
    let mut sim = sim("stranded_reseal", seed, NetWeights::default());
    let s = sim.add_server()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let d2 = sim.add_node(&[s], clock(&mut d))?;
    let d3 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d0, &[s])?.person;
    sim.pair(d0, d1, p)?;
    sim.pair(d0, d2, p)?;
    sim.pair(d0, d3, p)?;
    sim.item(d0, p)?;
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    let before = newest_read(&mut sim, d1, &p)?;
    sim.node_down(d1)?;
    // two removals: two rotations, two steps; the first step's claim set is dropped once it has
    // been superseded for MEMBERSHIP_KEEP
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
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    if newest_read(&mut sim, d1, &p)? != newest_read(&mut sim, d0, &p)? {
        return Err(sim.fail("the re-sealed device does not hold the person's newest epoch"));
    }
    sim.finish()
}

/// A server loses its data (spec/sync.md §6: a writer uploads every must-hold body the label
/// lacks): writers re-register the label and re-upload; the quiescent check finds every
/// must-hold body back.
pub fn server_loses_data(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x10);
    let mut sim = sim("server_loses_data", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let pa = sim.person(a, &[s])?.person;
    let pb = sim.person(b, &[s])?.person;
    sim.introduce(b, a)?;
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s])?;
    sim.grant(a, g, pb, Role::Write)?;
    sim.run_until_quiescent(40)?;
    sim.item(a, g)?;
    sim.run(150)?;
    sim.wipe_server(s)?;
    sim.run(150)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A node offline across rotations walks the steps (spec/sync.md §5 Open, Claim): a reader is
/// off while the admin removes another reader twice over (two rotations, two steps) and writes;
/// back online it walks by its stale sync key and reads; the removed readers hold no later
/// epoch.
pub fn offline_rotation(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x0f);
    let mut sim = sim("offline_rotation", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let e = sim.add_node(&[s], clock(&mut d))?;
    let pa = sim.person(a, &[s])?.person;
    let pb = sim.person(b, &[s])?.person;
    let pc = sim.person(c, &[s])?.person;
    let pe = sim.person(e, &[s])?.person;
    for n in [b, c, e] {
        sim.introduce(n, a)?;
    }
    sim.run_until_quiescent(40)?;
    let g = sim.group(a, pa, &[s])?;
    sim.grant(a, g, pb, Role::Read)?;
    sim.grant(a, g, pc, Role::Read)?;
    sim.run_until_quiescent(40)?;
    sim.grant(a, g, pe, Role::Write)?;
    sim.run_until_quiescent(40)?;
    sim.item(a, g)?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    sim.node_down(c)?;
    sim.remove(a, g, pb)?;
    sim.excused.insert(b);
    sim.run(60)?;
    sim.settle()?;
    let mid = newest_read(&mut sim, a, &g)?;
    sim.remove(a, g, pe)?;
    sim.excused.insert(e);
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    let now = newest_read(&mut sim, a, &g)?;
    if newest_read(&mut sim, c, &g)? != now {
        return Err(sim.fail("the reader back online does not hold the newest epoch"));
    }
    if newest_read(&mut sim, b, &g)?.is_some_and(|x| Some(x) >= mid) {
        return Err(sim.fail("a removed reader holds an epoch after its removal"));
    }
    if newest_read(&mut sim, e, &g)?.is_some_and(|x| Some(x) >= now) {
        return Err(sim.fail("a removed writer holds an epoch after its removal"));
    }
    sim.finish()
}

/// Disk loss and recovery from the card (spec/permissions.md §9): one of a person's two devices
/// loses its disk; a fresh device holding the card follows the home label, recovers (grants
/// itself admin, removes the lost device with the person's rotation) and converges with the
/// remaining device.
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
    sim.run(100)?;
    sim.lose_disk(d0)?;
    sim.run(50)?;
    let fresh = sim.add_node(&[s], clock(&mut d))?;
    let card = person.card.clone();
    let r = sim.engine(fresh)?.hold_key_actor(card.seed.clone());
    r.map_err(|e| sim.fail(format!("hold_key_actor: {e}")))?;
    let acts = sim.sync(fresh)?.follow(card.person, card.home_label, card.servers.clone());
    sim.actions(fresh, acts)?;
    for _ in 0..3 {
        sim.settle()?;
        sim.advance(61_000)?;
    }
    let lost = sim.tid(d0)?;
    let r = sim.engine(fresh)?.recover(&card, &[lost], PreSync::Synced);
    let done = r.map_err(|e| sim.fail(format!("recover: {e}")))?;
    sim.carry(fresh, done)?;
    sim.feed(fresh, Event::Local)?;
    sim.run(100)?;
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
