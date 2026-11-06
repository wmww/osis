//! Phase B scenarios: sync engines and hosts under message faults, partitions,
//! crashes and data loss. Each is a function of the seed; `crate::replay` reruns any. Setup runs
//! calm (no faults) and settles with `quiet`; `run` is the faulty random schedule; every
//! scenario ends with `run_until_quiescent` (the invariants of `check`).

use super::{LinkFaults, NetConfig, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{ClockSpec, Report, Res};
use crate::workload;
use osis_commit::PurgeItem;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, Role, Tid, Value, WallMs};
use osis_node::Mutation;
use osis_node::flows::PreSync;
use osis_node::sync::Event;
use osis_schema::RawKey;
use std::collections::BTreeSet;

pub const DAY_MS: u64 = 86_400_000;

pub fn lossy() -> LinkFaults {
    LinkFaults { cut_pct: 2, dup_pct: 1, max_delay_ms: 3_000 }
}

pub fn clock(d: &mut Dice) -> ClockSpec {
    ClockSpec { skew_ms: d.range_i64(-20_000, 20_000), drift_ppm: d.range_i64(-100, 100) }
}

pub fn sim(name: &str, seed: u64, weights: NetWeights) -> NetSim {
    NetSim::new(name, seed, NetConfig { faults: lossy(), weights, ..NetConfig::default() })
}

pub fn ak(sim: &NetSim, a: &osis_schema::Aspect<Value>) -> Res<Ak> {
    Ak::new(a.ak()).map_err(|e| sim.fail(e.to_string()))
}

/// Newest current read epoch of `g` whose secret node `n` holds.
pub fn newest_read(sim: &mut NetSim, n: usize, g: &Tid) -> Res<Option<u64>> {
    Ok(sim.engine(n)?.epochs(g).and_then(|e| e.read.newest_held().map(|x| x.0.n())))
}

/// Accounts on nodes `ns` (homes at `homes[i]`), each introduced to the first: the first node's
/// account and the others'.
pub fn persons<const N: usize>(sim: &mut NetSim, ns: [usize; N], homes: [usize; N]) -> Res<[Tid; N]> {
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
    ps.try_into().map_err(|_| sim.fail("accounts"))
}

/// A group of node `a`'s account at `hosts`, granted to each (account, role) in turn.
pub fn shared_group(sim: &mut NetSim, a: usize, pa: Tid, hosts: &[usize], grants: &[(Tid, Role)]) -> Res<Tid> {
    let g = sim.group(a, pa, hosts)?;
    for (p, r) in grants {
        sim.grant(a, g, *p, *r)?;
        sim.quiet(40)?;
    }
    Ok(g)
}

/// A purge of `c`'s `s:gone.0` delta on `t` by node `n` (spec/commits.md §5), recorded for the
/// purge invariant.
pub fn purge(sim: &mut NetSim, n: usize, c: osis_base::CommitId, t: Tid) -> Res<()> {
    sim.observe()?;
    let gone = ak(sim, &workload::GONE)?;
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone.clone() });
    m.remove_aspect(t, &workload::GONE).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    sim.purged.push((c, t, gone));
    Ok(())
}

/// Node `n` writes `s:gone.0` on `t`.
pub fn write_gone(sim: &mut NetSim, n: usize, t: Tid, v: &str) -> Res<osis_base::CommitId> {
    let mut m = Mutation::new();
    m.set(t, &workload::GONE, &Value::Str(v.into())).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))
}

/// Two nodes of one account through one host (spec/sync.md §2, §6): the account's
/// home label, the second node paired; both write items of the account's group under a lossy
/// network with crashes mid-write.
pub fn two_devices_host(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xb2);
    let mut sim = sim("two_devices_host", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_host()?;
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

/// Three accounts share a group through two replicating hosts (spec/sync.md §5 replication,
/// §6): A (admin, reaches both), B (writer, s0 only), C (reader, s1 only); grants by inbox;
/// host crashes mid-write, partitions.
pub fn three_persons_two_hosts(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x3b);
    let w = NetWeights { host_crash: 1, host_restart: 2, partition: 1, heal: 2, ..NetWeights::default() };
    let mut sim = sim("three_persons_two_hosts", seed, w);
    let s0 = sim.add_host()?;
    let s1 = sim.add_host()?;
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

/// A removed writer's bodies deleted by delete key (spec/sync.md §5 deletion by delete key; spec/commits.md
/// §5): W writes a writer-purgeable aspect, the admin removes W, then a remaining writer (no
/// delete key) purges W's body while the admin is away; it is gone from the host and from
/// every honest node.
pub fn removed_writer(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7e);
    let mut sim = sim("removed_writer", seed, NetWeights::default());
    let s = sim.add_host()?;
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
    // W forgets what it lost once the removal applies there (spec/permissions.md §3) and never
    // brings it back
    if sim.engine(w)?.role_on(&g).is_none() && sim.engine(w)?.header(&cw).is_some() {
        return Err(sim.fail("W kept its commit on a thing it no longer reads"));
    }
    if sim.engine(b)?.header(&cw).is_none() {
        return Err(sim.fail("B never received W's body"));
    }
    // the admin is away: B purges W's body and deletes it by delete key
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
/// covered bodies are deleted at the host once the snapshot is there; then a purge; no
/// ping-pong.
pub fn compaction(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc0);
    let mut sim = sim("compaction", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(60)?;
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
        return Err(sim.fail("compaction deleted nothing at the host"));
    }
    let c = write_gone(&mut sim, a, t, "later")?;
    sim.quiet(40)?;
    purge(&mut sim, b, c, t)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Deleted records in the logs of host `s`.
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

/// A reader relays (spec/sync.md §5, §6): two hosts that do not replicate; the writer reaches
/// only s0, a reader both, a second reader only s1; the second reader reads the writer's content
/// carried by the first. The readers open the label while the admin registers the steps of the
/// grants' rotations (an open answered with the old head follows the new one).
pub fn reader_relays(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x2e);
    let mut sim = sim("reader_relays", seed, NetWeights::default());
    let s0 = sim.add_host()?;
    let s1 = sim.add_host()?;
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

/// A stranded node re-sealed (spec/permissions.md §3, §4; notes/sync.md Limits): one node of
/// an account is off while two others are removed (the account rotates twice, the home label steps
/// twice) and stays off past `ROLE_KEEP`, so the host dropped the claim set it needs; it
/// cannot read the new epoch; re-paired over a direct connection it does.
pub fn stranded_reseal(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x5d);
    let mut sim = sim("stranded_reseal", seed, NetWeights::default());
    let s = sim.add_host()?;
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
        return Err(sim.fail("the removals did not rotate the account"));
    }
    sim.advance(ROLE_KEEP_MS + 2 * DAY_MS)?;
    sim.settle()?;
    sim.restart_node(d1)?;
    for _ in 0..4 {
        sim.advance(61_000)?;
        sim.settle()?;
    }
    if newest_read(&mut sim, d1, &p)? == after {
        return Err(sim.fail("the node past ROLE_KEEP was not stranded (it read the new epoch by claim)"));
    }
    // re-paired: a re-seal over the direct connection
    sim.pair(d0, d1, p)?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    if newest_read(&mut sim, d1, &p)? != newest_read(&mut sim, d0, &p)? {
        return Err(sim.fail("the re-sealed node does not hold the account's newest epoch"));
    }
    sim.finish()
}

/// A host loses its data (spec/sync.md §6: a writer uploads every must-hold body the label
/// lacks): writers re-register the labels and re-upload; the quiescent check finds every
/// must-hold body back.
pub fn host_loses_data(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x10);
    let mut sim = sim("host_loses_data", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(120)?;
    sim.wipe_host(s)?;
    sim.run(120)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A node offline across rotations walks the steps (spec/sync.md §5 Open, Claim): a reader is
/// off while the admin removes a reader and then a writer (two rotations, two steps) and keeps
/// writing; back online it walks by its stale sync key and reads; the removed holders hold no
/// later epoch.
pub fn offline_rotation(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x0f);
    let mut sim = sim("offline_rotation", seed, NetWeights::default());
    let s = sim.add_host()?;
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

/// A grant to a group (spec/sync.md §3): a thing granted to group H, with H's admin away at the
/// grant, reaches H's readers through the copy under H's label, a later reader too; a reader
/// removed from H holds no later epoch of the thing, the others do.
pub fn grant_to_group(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x93);
    let mut sim = sim("grant_to_group", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let e = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc, pe] = persons(&mut sim, [a, b, c, e], [s, s, s, s])?;
    let h = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Read), (pc, Role::Read)])?;
    let t = sim.group_with(a, pa, &[s], true)?;
    sim.item(a, t)?;
    sim.quiet(40)?;
    sim.grant(a, t, h, Role::Read)?;
    sim.run(30)?;
    sim.node_down(a)?;
    sim.run(20)?;
    sim.restart_node(a)?;
    sim.quiet(40)?;
    let now = newest_read(&mut sim, a, &t)?;
    if newest_read(&mut sim, b, &t)? != now || newest_read(&mut sim, c, &t)? != now {
        return Err(sim.fail("a reader of the group holds not the thing's newest epoch"));
    }
    sim.grant(a, h, pe, Role::Read)?;
    sim.run(30)?;
    sim.quiet(40)?;
    if newest_read(&mut sim, e, &t)? != now {
        return Err(sim.fail("a later reader of the group holds not the thing's newest epoch"));
    }
    sim.remove(a, h, pb)?;
    sim.excused.insert(b);
    sim.item(a, t)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    let now = newest_read(&mut sim, a, &t)?;
    if newest_read(&mut sim, b, &t)?.is_some_and(|x| Some(x) >= now) {
        return Err(sim.fail("a reader removed from the group holds the thing's epoch after it"));
    }
    if newest_read(&mut sim, c, &t)? != now || newest_read(&mut sim, e, &t)? != now {
        return Err(sim.fail("a staying reader of the group holds not the thing's newest epoch"));
    }
    // a grant of a thing with no label (spec/sync.md §2): the group's readers hold the role and
    // no route, shown at the granter and at a reader alike; the thing's first label is delivered
    // to the group and copied under its label, and they read it
    let u = sim.thing_with_secrets(a, pa)?;
    sim.grant(a, u, h, Role::Read)?;
    sim.run(30)?;
    sim.quiet(40)?;
    for n in [a, c] {
        if sim.engine(n)?.unrouted().get(&u).is_none_or(|hs| *hs != vec![h]) {
            return Err(sim.fail(format!("node {n} does not show the group without a route to the unsynced thing")));
        }
    }
    if newest_read(&mut sim, c, &u)?.is_some() {
        return Err(sim.fail("a reader of the group reads a thing nothing carries"));
    }
    let addrs = sim.addresses(&[s]);
    let r = sim.sync(a)?.create_label(&u, addrs);
    let (_, acts) = r.map_err(|e| sim.fail(format!("node {a} create_label: {e}")))?;
    sim.after_node(a, acts)?;
    sim.run(30)?;
    sim.run_until_quiescent(40)?;
    let now = newest_read(&mut sim, a, &u)?;
    if newest_read(&mut sim, c, &u)? != now || newest_read(&mut sim, e, &u)? != now {
        return Err(sim.fail("a reader of the group holds not the synced thing's epoch"));
    }
    for n in [a, c] {
        if sim.engine(n)?.unrouted().contains_key(&u) {
            return Err(sim.fail(format!("node {n} still shows the synced thing without a route")));
        }
    }
    sim.finish()
}

/// Disk loss and recovery from the card (spec/permissions.md §7): one of an account's two nodes
/// loses its disk; a fresh node holding the card follows the home label, recovers (grants
/// itself admin, removes the lost node with the account's rotation) and converges with the
/// remaining node.
pub fn disk_loss(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xd1);
    let mut sim = sim("disk_loss", seed, NetWeights::default());
    let s = sim.add_host()?;
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
    let rk = r.map_err(|e| sim.fail(format!("hold_key_actor: {e}")))?;
    let acts = sim.sync(fresh)?.follow(rk, card.person, card.home_label, card.hosts.clone());
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
            return Err(sim.fail(format!("node {n}: the account's roster after recovery: {:?}", roster.keys().collect::<Vec<_>>())));
        }
    }
    sim.finish()
}


/// A node restored from a backup of its store (spec/crdt.md §2.1): d0 is backed up, keeps
/// writing (random writes too) until its commits reached the host, then its store is replaced by
/// the backup and it writes at once, before any pass. The pass brings the lost commits; no
/// commit anywhere is void (spec/commits.md §4: overlapping counters void both).
pub fn restore_backup(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x8b);
    let mut sim = sim("restore_backup", seed, NetWeights::default());
    let s = sim.add_host()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d0, &[s])?.person;
    sim.pair(d0, d1, p)?;
    let items = [sim.item(d0, p)?, sim.item(d0, p)?];
    sim.run(80)?;
    sim.quiet(40)?;
    let backup = sim.backup_node(d0)?;
    set_all(&mut sim, d0, &items, "after the backup")?;
    sim.run(80)?;
    sim.quiet(40)?;
    sim.restore_node(d0, backup)?;
    set_all(&mut sim, d0, &items, "restored")?;
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    for n in [d0, d1] {
        let void: Vec<_> = sim.engine(n)?.core.ix.void.iter().copied().collect();
        if !void.is_empty() {
            return Err(sim.fail(format!("node {n}: void commits {void:?}")));
        }
    }
    sim.finish()
}

/// Node `n` sets `workload::REG` of each of `items` to `v`, in one commit.
fn set_all(sim: &mut NetSim, n: usize, items: &[Tid], v: &str) -> Res<()> {
    let mut m = Mutation::new();
    for t in items {
        m.set(*t, &workload::REG, &Value::Str(v.into())).map_err(|e| sim.fail(e.to_string()))?;
    }
    let r = sim.engine(n)?.commit(m);
    r.map_err(|e| sim.fail(format!("node {n} write: {e}")))?;
    sim.feed(n, Event::Local)
}

/// A grant whose inbox deposit is lost (spec/sync.md §3, §5): the admin's node crashes right
/// after granting, before the deposit reached the host; the grant reaches the grantee once the restarted node re-sends it.
pub fn grant_lost_on_crash(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x9c);
    let mut sim = sim("grant_lost_on_crash", seed, NetWeights::default());
    let s = sim.add_host()?;
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

/// Bytes of the chunks of `new`'s canonical encoding whose content `old`'s lacks: what any
/// content-defined writer must upload for the edit.
fn new_chunk_bytes(old: &[u8], new: &[u8]) -> u64 {
    let cuts = |d: &[u8]| -> Vec<Vec<u8>> {
        let e = osis_base::encode(&Value::Bytes(d.to_vec()));
        let mut out = Vec::new();
        let mut rest = e.as_slice();
        for n in osis_base::chunker::chunk_lengths(&e, osis_base::ChunkParams::FORMAT) {
            let (c, r) = rest.split_at(n.min(rest.len()));
            out.push(c.to_vec());
            rest = r;
        }
        out
    };
    let have: std::collections::BTreeSet<Vec<u8>> = cuts(old).into_iter().collect();
    cuts(new).into_iter().filter(|c| !have.contains(c)).map(|c| c.len() as u64).sum()
}

/// Two nodes of one account edit a large blob of many chunks in turn through one host
/// (spec/requirements.md Scale: a change inside a huge value costs O(change); spec/sync.md §1
/// chunk reuse): each reads the value whole (fetching the chunks it lacks), changes a few
/// bytes and writes it back; what it uploads per edit stays within 1.2x of the chunks the
/// edit changed, plus the tree's root node and a fixed allowance for the commit and protocol.
pub fn large_edits(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x1a);
    let mut sim = NetSim::new("large_edits", seed, NetConfig::default());
    let s = sim.add_host()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d0, &[s])?.person;
    sim.pair(d0, d1, p)?;
    let t = sim.item(d0, p)?;
    sim.quiet(40)?;
    let file = Ak::new("app:file.0").map_err(|e| sim.fail(e.to_string()))?;
    let mut cur = vec![0u8; 8 << 20];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(seed), &mut cur);
    let mut m = Mutation::new();
    m.set(t, &file, &Value::Bytes(cur.clone())).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(d0, m)?;
    sim.quiet(40)?;
    let chunks = osis_base::chunker::chunk_lengths(&osis_base::encode(&Value::Bytes(cur.clone())), osis_base::ChunkParams::FORMAT).len() as u64;
    for i in 0..8u64 {
        let n = if i % 2 == 0 { d1 } else { d0 };
        // the editor reads the value whole first
        let acts = sim.sync(n)?.fetch_missing();
        sim.actions(n, acts)?;
        sim.quiet(40)?;
        let read = sim.engine(n)?.get_full(&t, &file).map_err(|e| sim.fail(format!("node {n} read: {e}")))?;
        if read != Some(Value::Bytes(cur.clone())) {
            return Err(sim.fail(format!("edit {i}: node {n} reads another value")));
        }
        let old = cur.clone();
        let at = d.range_i64(0, cur.len() as i64) as usize;
        let mut bytes = vec![0u8; d.range_i64(1, 2000) as usize];
        osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(seed ^ i), &mut bytes);
        cur.splice(at..at, bytes);
        let sent0 = sim.nodes.get(n).map_or(0, |x| x.sent_bytes);
        let mut m = Mutation::new();
        m.set(t, &file, &Value::Bytes(cur.clone())).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(n, m)?;
        sim.quiet(40)?;
        let sent = sim.nodes.get(n).map_or(0, |x| x.sent_bytes) - sent0;
        let need = new_chunk_bytes(&old, &cur);
        // the root node (about 100 B per chunk link) and the commit, entries and requests
        let allowance = chunks * 120 + (32 << 10);
        sim.note(format!("edit {i} by node {n}: sent {sent} B, new chunks {need} B, value {} B", cur.len()));
        if sent * 10 > need * 12 + allowance * 10 {
            return Err(sim.fail(format!("edit {i} by node {n}: sent {sent} B for {need} B of new chunks")));
        }
    }
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Pass work sets against full passes (spec/sync.md §6, §7): two replicating hosts, an admin
/// and two writers writing at random under faults, then compactions (snapshots), keep-at-most
/// and expiring writes, a purge, a demotion of a writer, time past the bounds. Run as is and
/// under `with_full_passes`, it must give the same run (`core/test/sim/tests/it/work_sets.rs`).
pub fn work_sets(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x3e7);
    let mut sim = sim("work_sets", seed, NetWeights { partition: 1, heal: 2, ..NetWeights::default() });
    let s0 = sim.add_host()?;
    let s1 = sim.add_host()?;
    sim.replicate(s0, s1)?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let b = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s1], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s0, s0, s1])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.item(b, g)?;
    sim.quiet(40)?;
    sim.run(60)?;
    for k in 0..4u64 {
        let n = match d.below(3) {
            0 => a,
            1 => b,
            _ => c,
        };
        let mut m = Mutation::new();
        m.set(t, &workload::LATEST, &Value::Str(format!("s{k}"))).map_err(|e| sim.fail(e.to_string()))?;
        let e = sim.engine(n)?;
        let at = e.now().0 + (10 + d.below(20)) * 60_000;
        let x = e.new_thing(&mut m, g);
        m.persist(x);
        // the record and the plain write, then the expiring note (spec/commits.md §6)
        if !sim.write(n, m)?.is_empty() {
            let mut m = Mutation::new();
            m.set(x, &workload::NOTE, &Value::Str(format!("n{k}"))).map_err(|e| sim.fail(e.to_string()))?;
            m.expires(x, &workload::NOTE, WallMs(at)).map_err(|e| sim.fail(e.to_string()))?;
            sim.write(n, m)?;
        }
        sim.run(15)?;
    }
    sim.quiet(40)?;
    for (n, a_) in [(a, &workload::REG), (b, &workload::TAGS)] {
        let k = ak(&sim, a_)?;
        let acts = sim.sync(n)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
        sim.actions(n, acts)?;
        sim.run(20)?;
    }
    let gone = write_gone(&mut sim, b, t, "gone")?;
    sim.quiet(40)?;
    purge(&mut sim, a, gone, t)?;
    sim.run(30)?;
    sim.remove(a, g, pc)?;
    sim.excused.insert(c);
    sim.run(40)?;
    sim.advance(3_600_000)?;
    sim.run(30)?;
    sim.run_until_quiescent(60)?;
    sim.finish()
}

/// Role moves against work sets and the re-judged set (spec/sync.md §6, §7; the differential is
/// `core/test/sim/tests/it/work_sets.rs`): members added one by one under writes at skewed clocks,
/// a guest whose grant ends by the clock, a node paired to a member, a change of role, two
/// admins adding apart while one is removed (writes late, mid-history, flipped), a removal and a
/// new add of the one removed.
pub fn member_churn(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xadd);
    let mut sim = sim("member_churn", seed, NetWeights { partition: 1, heal: 2, ..NetWeights::default() });
    let s = sim.add_host()?;
    let ns: [usize; 6] = [
        sim.add_node(&[s], clock(&mut d))?,
        sim.add_node(&[s], clock(&mut d))?,
        sim.add_node(&[s], clock(&mut d))?,
        sim.add_node(&[s], clock(&mut d))?,
        sim.add_node(&[s], clock(&mut d))?,
        sim.add_node(&[s], clock(&mut d))?,
    ];
    let [a, b, c, e, f, h] = ns;
    let [pa, pb, pc, pe, pf, ph] = persons(&mut sim, ns, [s; 6])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Admin)])?;
    let t = sim.item(a, g)?;
    let write = |sim: &mut NetSim, d: &mut Dice, n: usize, k: u64| -> Res<()> {
        let mut m = Mutation::new();
        m.set(t, &workload::REG, &Value::Str(format!("n{n} {k}"))).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(n, m)?;
        sim.run(d.below(4))
    };
    sim.quiet(40)?;
    // added one by one, with writes between
    for (i, (p, n)) in [(pc, c), (pe, e)].into_iter().enumerate() {
        write(&mut sim, &mut d, a, i as u64)?;
        sim.grant(a, g, p, Role::Write)?;
        sim.run(10)?;
        sim.quiet(40)?;
        write(&mut sim, &mut d, n, 10 + i as u64)?;
        write(&mut sim, &mut d, b, 20 + i as u64)?;
    }
    sim.quiet(40)?;
    // a guest: its grant ends by the clock
    let at = sim.engine(a)?.now().0 + 600_000;
    let edge = osis_schema::core_types::Edge { role: Role::Write, until: Some(WallMs(at)), invite: None, tied: None };
    let r = sim.engine(a)?.grant(&g, &pf, &edge);
    let done = r.map_err(|e| sim.fail(format!("guest: {e}")))?;
    sim.carry(a, done)?;
    sim.quiet(40)?;
    write(&mut sim, &mut d, f, 30)?;
    sim.advance(700_000)?;
    sim.excused.insert(f);
    sim.run(20)?;
    sim.quiet(40)?;
    // one of a member's nodes more, then a role lowered and raised
    let extra = sim.add_node(&[s], clock(&mut d))?;
    sim.pair(c, extra, pc)?;
    sim.quiet(40)?;
    write(&mut sim, &mut d, extra, 40)?;
    let lower = osis_node::flows::Demotion { holder: pe, new: Some(osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, tied: None }), presync: PreSync::Synced, keep: None };
    let r = sim.engine(a)?.demote(&g, &lower);
    let done = r.map_err(|e| sim.fail(format!("lower: {e}")))?;
    sim.carry(a, done)?;
    sim.quiet(40)?;
    sim.grant(a, g, pe, Role::Write)?;
    sim.quiet(40)?;
    // two admins apart: one adds, the other adds and is removed by the first
    sim.partition(Party::N(b), Party::S(s));
    sim.grant(a, g, ph, Role::Write)?;
    sim.grant(b, g, pf, Role::Write)?;
    write(&mut sim, &mut d, a, 50)?;
    write(&mut sim, &mut d, b, 51)?;
    sim.run(10)?;
    sim.remove(a, g, pb)?;
    sim.run(10)?;
    sim.heal(Party::N(b), Party::S(s));
    sim.excused.insert(b);
    sim.run(40)?;
    sim.quiet(40)?;
    write(&mut sim, &mut d, h, 60)?;
    // out and back
    sim.remove(a, g, pc)?;
    sim.quiet(40)?;
    sim.grant(a, g, pc, Role::Write)?;
    sim.run(30)?;
    write(&mut sim, &mut d, a, 70)?;
    sim.run_until_quiescent(60)?;
    sim.finish()
}

/// A snapshot dropped under a cover that turns invalid (spec/permissions.md §5.2, spec/sync.md
/// §6, §7): A compacts the tags (S1); while A is away, C writes and compacts over it (S2) and W
/// drops S1 under S2's cover, deleting it at the host; A, not having seen S2, removes C (S2
/// invalid). S1 is missing again at W; A, holding it uncovered, uploads it again while it has a
/// live write; W fetches it, and A and W read alike. Random writes while A is away: a part W
/// dropped under S2 and deleted reaches A never, and its commit applies there without it
/// (S2 lists it, spec/commits.md §4).
pub fn coverer_revoked(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc5);
    let mut sim = sim("coverer_revoked", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let w = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pc, pw] = persons(&mut sim, [a, c, w], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pc, Role::Write), (pw, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    sim.run(40)?;
    let k = ak(&sim, &workload::TAGS)?;
    let add = |sim: &mut NetSim, n: usize, v: &str| -> Res<()> {
        let mut m = Mutation::new();
        m.op(t, &workload::TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Str(v.into())) }).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(n, m)?.map(|_| ()).ok_or_else(|| sim.fail(format!("node {n} wrote nothing")))
    };
    add(&mut sim, a, "by a")?;
    sim.quiet(40)?;
    let snaps = |sim: &mut NetSim, n: usize| -> Res<BTreeSet<osis_base::CommitId>> {
        let e = sim.engine(n)?;
        Ok(e.commit_ids().into_iter().filter(|x| e.header(x).is_some_and(|h| h.kind == osis_commit::Kind::ContentSnapshot && h.aspects.iter().any(|y| y.tid == t && y.ak == k))).collect())
    };
    let before = snaps(&mut sim, a)?;
    let acts = sim.sync(a)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {a} compact: {e}")))?;
    sim.actions(a, acts)?;
    let s1 = snaps(&mut sim, a)?.difference(&before).next().copied().ok_or_else(|| sim.fail("A wrote no snapshot"))?;
    sim.quiet(40)?;
    sim.sever(Party::N(a), Party::S(s));
    // a write of C's first: S2 covers S1 strictly (of covered-equal ones the higher ID goes)
    add(&mut sim, c, "by c")?;
    sim.run(10)?;
    let acts = sim.sync(c)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {c} compact: {e}")))?;
    sim.actions(c, acts)?;
    sim.run(20)?;
    // past `MAX_DRIFT`: W drops S1 under S2 and deletes it at the host
    sim.advance(2 * 3_600_000)?;
    sim.quiet(40)?;
    // (dropped, missing) of S1's part at W
    let part = |sim: &mut NetSim| -> Res<Option<(bool, bool)>> {
        let e = sim.engine(w)?;
        let Some(m) = e.core.ix.commits.get(&s1) else { return Ok(None) };
        Ok(m.view.aspects.iter().position(|x| x.tid == t && x.ak == k).map(|ai| (m.dropped.contains_key(&ai), m.missing.contains(&ai))))
    };
    if part(&mut sim)? != Some((true, false)) {
        return Err(sim.fail("W did not drop S1 under S2"));
    }
    sim.remove(a, g, pc)?;
    sim.excused.insert(c);
    sim.unsever(Party::N(a), Party::S(s));
    sim.run(40)?;
    sim.run_until_quiescent(60)?;
    // A uploads S1 again only while it has a live write (spec/sync.md §6): random writes may
    // have removed them all
    let p = part(&mut sim)?;
    let live = sim.engine(a)?.body_live(&s1, &t, &k).map_err(|e| sim.fail(e.to_string()))?;
    if p != Some((false, false)) && live {
        return Err(sim.fail(format!("W never got S1 back: {p:?}")));
    }
    sim.finish()
}

/// Snapshot rights end to end (spec/commits.md §5, spec/sync.md §6, §7, spec/permissions.md §6):
/// the seed picks a purge set, a keep bound and a mix of compacters among an admin and two plain
/// writers, under faults. A body stays at the host and reaches a node coming fresh unless a
/// compacter holding the right over it wrote a snapshot after it; such a body leaves the host
/// (another right holder that never held that snapshot, superseded early, may keep its copy).
/// Everyone reads alike, the fresh node too, whichever bodies it got; the labels go quiet
/// (`finish`: no upload and delete loop).
pub fn snapshot_rights(seed: u64) -> Res<Report> {
    use osis_proto::LabelStore;
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut d = Dice::new(seed ^ 0x5a9);
    let by = PurgeBy::from_id(d.below(5)).unwrap_or_default();
    // 0: no bound; 1: keep at least; 2: keep at most under `writer` (dead bodies go whoever compacts)
    let bound = match d.below(3) {
        2 if by != PurgeBy::Writer => 0,
        x => x,
    };
    let half_hour = Bound { rel: Some(1_800_000), abs: None };
    let replaced = Bound { rel: Some(0), abs: None };
    let keep = Retention { by, at_least: if bound == 1 { half_hour } else { Bound::default() }, at_most: if bound == 2 { replaced } else { Bound::default() } };
    let mut sim = sim("snapshot_rights", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let w = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pw] = persons(&mut sim, [a, b, w], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pw, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    let k = ak(&sim, &workload::REG)?;
    // who holds the right over a body of `author` (node), for this set
    let right = |n: usize, author: usize| (n == a && by.admin()) || by.writer() || (n == author && by.author());
    // two rounds of overwrites, each followed by the seed's compacters
    let mut written: Vec<(osis_base::CommitId, usize, bool)> = Vec::new();
    for round in 0..2 {
        for (i, (n, person)) in [(a, pa), (b, pb), (w, pw)].into_iter().cycle().take(6).enumerate() {
            let mut m = Mutation::new();
            // as the app writes: for the account, so any of its nodes holds the author's right
            m.act_as(person);
            m.retention(t, &workload::REG, keep).map_err(|e| sim.fail(e.to_string()))?;
            m.set(t, &workload::REG, &Value::Str(format!("v{round}.{i}"))).map_err(|e| sim.fail(e.to_string()))?;
            if let Some(c) = sim.commit(n, m)? {
                written.push((c, n, false));
            }
            sim.quiet(40)?;
        }
        for n in [a, b, w] {
            if d.below(2) == 0 {
                let acts = sim.sync(n)?.compact(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
                sim.actions(n, acts)?;
                sim.quiet(40)?;
                for x in written.iter_mut() {
                    x.2 |= right(n, x.1);
                }
            }
        }
    }
    // past `MAX_DRIFT`: right holders have dropped what they may
    sim.advance(2 * 3_600_000)?;
    sim.quiet(40)?;
    sim.run_until_quiescent(60)?;
    let fresh = sim.add_node(&[s], clock(&mut d))?;
    sim.pair(b, fresh, pb)?;
    sim.quiet(40)?;
    sim.run(40)?;
    // the author's other node compacts with its right; a body whose live write it lacks stays
    // uncovered, so what it may drop is not certain to go
    let fresh_compacted = d.below(2) == 0;
    if fresh_compacted {
        let acts = sim.sync(fresh)?.compact(&t, &k).map_err(|e| sim.fail(format!("fresh compact: {e}")))?;
        sim.actions(fresh, acts)?;
        sim.quiet(40)?;
    }
    sim.run_until_quiescent(60)?;
    let l = sim.sync(a)?.labels().into_iter().find(|x| x.0 == g).map(|x| x.1.id).ok_or_else(|| sim.fail("no label"))?;
    let live: BTreeSet<osis_base::BlobId> = sim.hub(s).ok_or_else(|| sim.fail("no hub"))?.store().live_ids(&l).map_err(|e| sim.fail(e.to_string()))?.into_iter().collect();
    let entries = sim.sync(a)?.entries(&l);
    let at_host = |c: &osis_base::CommitId| entries.iter().any(|(id, x)| live.contains(id) && matches!(x, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c));
    for (c, author, gone) in &written {
        // past its bound at a, by a margin for the others' clocks and deaths (random writes go on)
        let e = sim.engine(a)?;
        let (now, kept) = (e.now().0, e.body_keep(c, &t, &k));
        let dead = bound == 2 && kept.map_err(|x| sim.fail(x.to_string()))?.at_most.is_some_and(|m| m + 600_000 <= now);
        let gone = &(*gone || dead);
        // under keep at least a compacter's snapshot may be superseded before the bound passes: the
        // body then waits for the next snapshot with the right, so only what stays is certain
        let may_go = *gone || bound == 2 || (fresh_compacted && right(b, *author));
        if (*gone && bound != 1 && at_host(c)) || (!may_go && !at_host(c)) {
            return Err(sim.fail(format!("{by:?} bound {bound}: body of node {author} at the host {}, should be gone {gone}", !*gone)));
        }
        for n in [a, b, w, fresh] {
            let e = sim.engine(n)?;
            let m = e.core.ix.commits.get(c);
            let held = m.is_some_and(|m| m.view.aspects.iter().position(|x| x.tid == t && x.ak == k).is_some_and(|ai| !m.dropped.contains_key(&ai) && !m.missing.contains(&ai)));
            if !may_go && !held {
                return Err(sim.fail(format!("{by:?} bound {bound}: kept body of node {author} not held at node {n}")));
            }
            if dead && held {
                return Err(sim.fail(format!("{by:?}: body past keep at most held at node {n}")));
            }
        }
    }
    let reads: Vec<Option<Value>> = [a, b, w, fresh].into_iter().map(|n| sim.engine(n).map(|e| e.get_typed(&t, &workload::REG).ok().flatten())).collect::<Res<_>>()?;
    if reads.windows(2).any(|x| x.first() != x.last()) {
        return Err(sim.fail(format!("{by:?}: reads differ: {reads:?}")));
    }
    sim.finish()
}
