//! Phase B scenarios: sync engines and hosts under message faults, partitions,
//! crashes and data loss. Each is a function of its seeds; `crate::replay` reruns any. The setup
//! runs calm (no faults), settles with `quiet` and is shared by a sweep's seeds (`setup`,
//! `NetSim::setup`); `run` is the faulty random schedule; every scenario ends with
//! `run_until_quiescent` (the invariants of `check`).

use super::{LinkFaults, NetConfig, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{ClockSpec, Report, Res, Seeds};
use crate::reach::Uplink;
use crate::workload;
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{Ak, LabelId, Role, Tid, Value, WallMs};
use osis_node::Mutation;
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

/// A sim under `weights` and lossy links.
pub fn sim(name: &str, seed: u64, weights: NetWeights) -> NetSim {
    NetSim::new(name, seed, NetConfig { faults: lossy(), weights, ..NetConfig::default() })
}

/// Scenario `name`'s calm setup (`NetSim::setup`) under `weights` and lossy links.
pub fn setup<T: Clone + Send + 'static>(name: &str, s: Seeds, weights: NetWeights, build: impl FnOnce(&mut NetSim) -> Res<T>) -> Res<(NetSim, T)> {
    NetSim::setup(name, "", s, NetConfig { faults: lossy(), weights, ..NetConfig::default() }, build)
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
        ps.push(sim.account(*n, &[h])?.account);
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
    m.purge_commit(c, t, gone.clone());
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
pub fn two_nodes_host(s: Seeds) -> Res<Report> {
    two_nodes_host_under(s, lossy())
}

/// `two_nodes_host` under link faults `faults`.
pub fn two_nodes_host_under(s: Seeds, faults: LinkFaults) -> Res<Report> {
    let (mut sim, ()) = setup("two_nodes_host", s, NetWeights { crash: 1, restart: 2, ..NetWeights::default() }, |sim| {
        let mut d = Dice::new(sim.seed ^ 0xb2);
        let s = sim.add_host()?;
        let d0 = sim.add_node(&[s], clock(&mut d))?;
        let d1 = sim.add_node(&[s], clock(&mut d))?;
        let p = sim.account(d0, &[s])?.devices;
        sim.pair(d0, d1)?;
        sim.item(d0, p)?;
        sim.item(d0, p)?;
        Ok(())
    })?;
    sim.cfg.faults = faults;
    sim.run(200)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Three accounts share a group through two hosts (spec/sync.md §5, §6): A (admin, reaches
/// both, the only way data crosses between them), B (writer, s0 only), C (reader, s1 only);
/// grants by inbox; host crashes mid-write, partitions.
pub fn three_accounts_two_hosts(s: Seeds) -> Res<Report> {
    let w = NetWeights { host_crash: 1, host_restart: 2, partition: 1, heal: 2, ..NetWeights::default() };
    let (mut sim, ()) = setup("three_accounts_two_hosts", s, w, |sim| {
        let mut d = Dice::new(sim.seed ^ 0x3b);
        let s0 = sim.add_host()?;
        let s1 = sim.add_host()?;
        let a = sim.add_node(&[s0, s1], clock(&mut d))?;
        let b = sim.add_node(&[s0], clock(&mut d))?;
        let c = sim.add_node(&[s1], clock(&mut d))?;
        sim.sever(Party::N(b), Party::S(s1));
        sim.sever(Party::N(c), Party::S(s0));
        let [pa, pb, pc] = persons(sim, [a, b, c], [s0, s0, s1])?;
        let g = shared_group(sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Read)])?;
        sim.item(a, g)?;
        sim.item(a, g)?;
        sim.quiet(40)
    })?;
    sim.run(200)?;
    sim.run_until_quiescent(60)?;
    sim.finish()
}

/// A removed writer's bodies deleted by delete key (spec/sync.md §5 deletion by delete key; spec/commits.md
/// §5): W writes a writer-purgeable aspect, the admin removes W, then a remaining writer (no
/// delete key) purges W's body while the admin is away; it is gone from the host and from
/// every honest node.
pub fn removed_writer(s: Seeds) -> Res<Report> {
    let (mut sim, (a, b, w, pw, g, t)) = setup("removed_writer", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x7e);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let w = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb, pw] = persons(sim, [a, b, w], [s, s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pb, Role::Write), (pw, Role::Write)])?;
        let t = sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((a, b, w, pw, g, t))
    })?;
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
pub fn compaction(s: Seeds) -> Res<Report> {
    let (mut sim, (s, a, b, t)) = setup("compaction", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0xc0);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb] = persons(sim, [a, b], [s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pb, Role::Write)])?;
        let t = sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((s, a, b, t))
    })?;
    sim.run(60)?;
    sim.quiet(40)?;
    let live0 = live_at(&sim, s);
    for (n, a_) in [(a, &workload::REG), (b, &workload::TAGS), (a, &workload::MAP)] {
        let k = ak(&sim, a_)?;
        let acts = sim.sync(n)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
        sim.actions(n, acts)?;
        sim.run(30)?;
    }
    sim.run_until_quiescent(40)?;
    let live = live_at(&sim, s);
    if live0.iter().all(|x| live.contains(x)) {
        return Err(sim.fail("compaction deleted nothing at the host"));
    }
    let c = write_gone(&mut sim, a, t, "later")?;
    sim.quiet(40)?;
    purge(&mut sim, b, c, t)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// The live entries of host `s`.
fn live_at(sim: &NetSim, s: usize) -> BTreeSet<(LabelId, osis_base::BlobId)> {
    use osis_proto::LabelStore;
    let Some(h) = sim.hub(s) else { return BTreeSet::new() };
    let held = h.store().labels_after(None, 4096).unwrap_or_default();
    held.into_iter().flat_map(|l| h.store().live_ids(&l).unwrap_or_default().into_iter().map(move |b| (l, b))).collect()
}

/// A reader relays (spec/sync.md §5, §6): two hosts; the writer reaches
/// only s0, a reader both, a second reader only s1; the second reader reads the writer's content
/// carried by the first. The readers open the label while the admin registers the steps of the
/// grants' rotations (an open answered with the old head follows the new one).
pub fn reader_relays(s: Seeds) -> Res<Report> {
    let (mut sim, (a, s1)) = setup("reader_relays", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x2e);
        let s0 = sim.add_host()?;
        let s1 = sim.add_host()?;
        let a = sim.add_node(&[s0, s1], clock(&mut d))?;
        let r = sim.add_node(&[s0, s1], clock(&mut d))?;
        let c = sim.add_node(&[s1], clock(&mut d))?;
        sim.sever(Party::N(c), Party::S(s0));
        let [pa, pr, pc] = persons(sim, [a, r, c], [s0, s0, s1])?;
        let g = shared_group(sim, a, pa, &[s0, s1], &[(pr, Role::Read), (pc, Role::Read)])?;
        sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((a, s1))
    })?;
    // from now on the writer reaches s0 only
    sim.sever(Party::N(a), Party::S(s1));
    sim.run(120)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A stranded node re-sealed (spec/permissions.md §3, §4; notes/label-access.md Limits): one node of
/// an account is off while two others are removed (the account rotates twice, the home label steps
/// twice) and stays off past `ROLE_KEEP`, so the host dropped the claim set it needs; it
/// cannot read the new epoch; re-paired over a direct connection it does.
pub fn stranded_reseal(s: Seeds) -> Res<Report> {
    let (mut sim, (d0, d1, d2, d3, p)) = setup("stranded_reseal", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x5d);
        let s = sim.add_host()?;
        let d0 = sim.add_node(&[s], clock(&mut d))?;
        let d1 = sim.add_node(&[s], clock(&mut d))?;
        let d2 = sim.add_node(&[s], clock(&mut d))?;
        let d3 = sim.add_node(&[s], clock(&mut d))?;
        let p = sim.account(d0, &[s])?.devices;
        for x in [d1, d2, d3] {
            sim.pair(d0, x)?;
        }
        sim.item(d0, p)?;
        Ok((d0, d1, d2, d3, p))
    })?;
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
    sim.pair(d0, d1)?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    if newest_read(&mut sim, d1, &p)? != newest_read(&mut sim, d0, &p)? {
        return Err(sim.fail("the re-sealed node does not hold the account's newest epoch"));
    }
    sim.finish()
}

/// A host loses its data (spec/sync.md §6: a writer places every must-hold body the label
/// lacks): writers re-register the labels and place again; the quiescent check finds every
/// must-hold body back.
pub fn host_loses_data(s: Seeds) -> Res<Report> {
    let (mut sim, s) = setup("host_loses_data", s, NetWeights { crash: 1, restart: 2, ..NetWeights::default() }, |sim| {
        let mut d = Dice::new(sim.seed ^ 0x10);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb] = persons(sim, [a, b], [s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pb, Role::Write)])?;
        sim.item(a, g)?;
        sim.quiet(40)?;
        Ok(s)
    })?;
    sim.run(120)?;
    sim.wipe_host(s)?;
    sim.run(120)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// A node offline across rotations catches up (spec/sync.md §5 Opens, Behind): a reader is
/// off while the admin removes a reader and then a writer (two rotations, two steps) and keeps
/// writing; back online it asks by its stale sync key and reads; the removed holders hold no
/// later epoch.
pub fn offline_rotation(s: Seeds) -> Res<Report> {
    let (mut sim, (a, b, c, e, pb, pe, g)) = setup("offline_rotation", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x0f);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let c = sim.add_node(&[s], clock(&mut d))?;
        let e = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb, pc, pe] = persons(sim, [a, b, c, e], [s, s, s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pb, Role::Read), (pc, Role::Read), (pe, Role::Write)])?;
        sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((a, b, c, e, pb, pe, g))
    })?;
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
pub fn grant_to_group(s: Seeds) -> Res<Report> {
    let (mut sim, (a, b, c, e, pa, pb, pe, h, t)) = setup("grant_to_group", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x93);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let c = sim.add_node(&[s], clock(&mut d))?;
        let e = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb, pc, pe] = persons(sim, [a, b, c, e], [s, s, s, s])?;
        let h = shared_group(sim, a, pa, &[s], &[(pb, Role::Read), (pc, Role::Read)])?;
        let t = sim.group_with(a, pa, &[s], true)?;
        sim.item(a, t)?;
        sim.quiet(40)?;
        sim.grant(a, t, h, Role::Read)?;
        Ok((a, b, c, e, pa, pb, pe, h, t))
    })?;
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
    // a thing with secrets and so its own sync ID (spec/sync.md §2), granted to the group: its
    // readers read it through that sync ID
    let u = sim.thing_with_secrets(a, pa)?;
    sim.grant(a, u, h, Role::Read)?;
    sim.run(30)?;
    sim.run_until_quiescent(40)?;
    let now = newest_read(&mut sim, a, &u)?;
    if newest_read(&mut sim, c, &u)? != now || newest_read(&mut sim, e, &u)? != now {
        return Err(sim.fail("a reader of the group holds not the thing's epoch"));
    }
    sim.finish()
}

/// A node restored from a backup of its store (spec/crdt.md §2.1): d0 is backed up, keeps
/// writing (random writes too) until its commits reached the host, then its store is replaced by
/// the backup and it writes at once, before any pass. The pass brings the lost commits; no
/// commit anywhere is void (spec/commits.md §4: overlapping counters void both).
pub fn restore_backup(s: Seeds) -> Res<Report> {
    let (mut sim, (d0, d1, items)) = setup("restore_backup", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x8b);
        let s = sim.add_host()?;
        let d0 = sim.add_node(&[s], clock(&mut d))?;
        let d1 = sim.add_node(&[s], clock(&mut d))?;
        let p = sim.account(d0, &[s])?.devices;
        sim.pair(d0, d1)?;
        let items = [sim.item(d0, p)?, sim.item(d0, p)?];
        Ok((d0, d1, items))
    })?;
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
pub fn grant_lost_on_crash(s: Seeds) -> Res<Report> {
    let (mut sim, (a, pb, g)) = setup("grant_lost_on_crash", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x9c);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb] = persons(sim, [a, b], [s, s])?;
        let g = sim.group(a, pa, &[s])?;
        sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((a, pb, g))
    })?;
    sim.grant(a, g, pb, Role::Read)?;
    sim.node_down(a)?;
    sim.restart_node(a)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Bytes of the chunks of `new`'s canonical encoding whose content `old`'s lacks: what any
/// content-defined writer must place for the edit.
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
/// bytes and writes it back; what it places per edit stays within 1.2x of the chunks the
/// edit changed, plus the tree's root node and a fixed allowance for the commit and protocol.
pub fn large_edits(s: Seeds) -> Res<Report> {
    let seed = s.seed;
    let (mut sim, (d0, d1, t)) = NetSim::setup("large_edits", "", s, NetConfig::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x1a);
        let s = sim.add_host()?;
        let d0 = sim.add_node(&[s], clock(&mut d))?;
        let d1 = sim.add_node(&[s], clock(&mut d))?;
        let p = sim.account(d0, &[s])?.devices;
        sim.pair(d0, d1)?;
        let t = sim.item(d0, p)?;
        sim.quiet(40)?;
        Ok((d0, d1, t))
    })?;
    let mut d = Dice::new(seed ^ 0x1a);
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

/// Pass work sets against full passes (spec/sync.md §6, §7): two hosts, an admin and a writer
/// reaching both and a writer reaching s1 only, writing at random under faults, then compactions (snapshots), purge-on-replace
/// and expiring writes, a purge, a demotion of a writer, time past the bounds. Run as is and
/// under `with_full_passes`, it must give the same run (`core/test/sim/tests/it/work_sets.rs`).
pub fn work_sets(s: Seeds) -> Res<Report> {
    let (mut sim, (a, b, c, pc, g, t)) = setup("work_sets", s, NetWeights { partition: 1, heal: 2, ..NetWeights::default() }, |sim| {
        let mut d = Dice::new(sim.seed ^ 0x3e7);
        let s0 = sim.add_host()?;
        let s1 = sim.add_host()?;
        let a = sim.add_node(&[s0, s1], clock(&mut d))?;
        let b = sim.add_node(&[s0, s1], clock(&mut d))?;
        let c = sim.add_node(&[s1], clock(&mut d))?;
        let [pa, pb, pc] = persons(sim, [a, b, c], [s0, s0, s1])?;
        let g = shared_group(sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Write)])?;
        let t = sim.item(a, g)?;
        sim.item(b, g)?;
        let mut m = Mutation::new();
        let latest = ak(sim, &workload::LATEST)?;
        m.set(t, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(latest, osis_schema::History::PurgeOnReplace)).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(a, m)?;
        sim.quiet(40)?;
        Ok((a, b, c, pc, g, t))
    })?;
    let mut d = Dice::new(s.seed ^ 0x3e7);
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
        let acts = sim.sync(n)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
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
pub fn member_churn(s: Seeds) -> Res<Report> {
    let seed = s.seed;
    let (mut sim, (s, ns, [pb, pc, pe, pf, ph], g, t)) = setup("member_churn", s, NetWeights { partition: 1, heal: 2, ..NetWeights::default() }, |sim| {
        let mut d = Dice::new(sim.seed ^ 0xadd);
        let s = sim.add_host()?;
        let ns: [usize; 6] = [
            sim.add_node(&[s], clock(&mut d))?,
            sim.add_node(&[s], clock(&mut d))?,
            sim.add_node(&[s], clock(&mut d))?,
            sim.add_node(&[s], clock(&mut d))?,
            sim.add_node(&[s], clock(&mut d))?,
            sim.add_node(&[s], clock(&mut d))?,
        ];
        let [pa, pb, pc, pe, pf, ph] = persons(sim, ns, [s; 6])?;
        let g = shared_group(sim, ns[0], pa, &[s], &[(pb, Role::Admin)])?;
        let t = sim.item(ns[0], g)?;
        sim.quiet(40)?;
        Ok((s, ns, [pb, pc, pe, pf, ph], g, t))
    })?;
    let mut d = Dice::new(seed ^ 0xadd);
    let [a, b, c, e, f, h] = ns;
    let write = |sim: &mut NetSim, d: &mut Dice, n: usize, k: u64| -> Res<()> {
        let mut m = Mutation::new();
        m.set(t, &workload::REG, &Value::Str(format!("n{n} {k}"))).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(n, m)?;
        sim.run(d.below(4))
    };
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
    sim.pair(c, extra)?;
    sim.quiet(40)?;
    write(&mut sim, &mut d, extra, 40)?;
    let lower = osis_node::flows::Demotion { holder: pe, new: Some(osis_schema::core_types::Edge { role: Role::Read, until: None, invite: None, tied: None }), retain: None };
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
/// invalid). S1 is missing again at W; A, holding it uncovered, places it again while it has a
/// live write; W fetches it, and A and W read alike. Random writes while A is away: a part W
/// dropped under S2 and deleted reaches A never, and its commit applies there without it
/// (S2 lists it, spec/commits.md §4). A snapshot of A's or W's after S1 (W's own trigger before
/// the removal reached it, over S2 then valid) carries S1's writes and may keep S1 dropped at W:
/// then A and W must read alike.
pub fn coverer_revoked(s: Seeds) -> Res<Report> {
    let (mut sim, (s, a, c, w, pc, g, t)) = setup("coverer_revoked", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0xc5);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let c = sim.add_node(&[s], clock(&mut d))?;
        let w = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pc, pw] = persons(sim, [a, c, w], [s, s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pc, Role::Write), (pw, Role::Write)])?;
        let t = sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((s, a, c, w, pc, g, t))
    })?;
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
    let acts = sim.sync(a)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("node {a} compact: {e}")))?;
    sim.actions(a, acts)?;
    let s1 = snaps(&mut sim, a)?.difference(&before).next().copied().ok_or_else(|| sim.fail("A wrote no snapshot"))?;
    sim.quiet(40)?;
    sim.sever(Party::N(a), Party::S(s));
    // a write of C's first: S2 covers S1 strictly (of covered-equal ones the higher ID goes)
    add(&mut sim, c, "by c")?;
    sim.run(10)?;
    let before_c = snaps(&mut sim, c)?;
    let acts = sim.sync(c)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("node {c} compact: {e}")))?;
    sim.actions(c, acts)?;
    let s2: BTreeSet<_> = snaps(&mut sim, c)?.difference(&before_c).copied().collect();
    sim.run(20)?;
    // past `MAX_DRIFT`: W drops S1 under S2 and deletes it at the host
    sim.advance(2 * 3_600_000)?;
    sim.quiet(40)?;
    // (dropped, missing) of S1's part at W
    let part = |sim: &mut NetSim| -> Res<Option<(bool, bool)>> {
        let e = sim.engine(w)?;
        let Some(m) = e.core.ix.commits.get(&s1) else { return Ok(None) };
        Ok(m.view.aspects.iter().position(|x| x.tid == t && x.ak == k).map(|ai| (m.is_dropped(ai), m.missing(ai))))
    };
    if part(&mut sim)? != Some((true, false)) {
        return Err(sim.fail("W did not drop S1 under S2"));
    }
    sim.remove(a, g, pc)?;
    sim.excused.insert(c);
    sim.unsever(Party::N(a), Party::S(s));
    sim.run(40)?;
    sim.run_until_quiescent(60)?;
    // A places S1 again only while it has a live write (spec/sync.md §6): random writes may
    // have removed them all
    let p = part(&mut sim)?;
    let live = sim.engine(a)?.delta_live(&s1, &t, &k).map_err(|e| sim.fail(e.to_string()))?;
    let s1_ts = sim.engine(a)?.header(&s1).map(|h| h.ts);
    let later = snaps(&mut sim, w)?.into_iter().any(|x| x != s1 && !s2.contains(&x) && sim.engine(w).ok().and_then(|e| e.header(&x)).is_some_and(|h| h.author != pc && Some(h.ts) > s1_ts));
    let alike = sim.engine(a)?.get(&t, &k).ok() == sim.engine(w)?.get(&t, &k).ok();
    if p != Some((false, false)) && live && !(later && alike) {
        return Err(sim.fail(format!("W never got S1 back: {p:?}")));
    }
    sim.finish()
}

/// Snapshot rights end to end (spec/commits.md §5, spec/sync.md §6, §7, spec/permissions.md §6):
/// the seed picks a purge set, the thing's setting and a mix of compacters among an admin and two
/// plain writers, under faults. A body stays at the host and reaches a node coming fresh unless it
/// is replaced and a compacter wrote a snapshot after it (once out of history any writer's cover
/// drops it; a live body stays where the setting keeps it while live, spec/commits.md §5 Kept
/// while live, and is covered like a replaced one where it does not); such a body
/// leaves the host (a node that never held that snapshot, superseded early, may keep its copy).
/// Everyone reads alike, the fresh node too, whichever bodies it got; the labels go quiet
/// (`finish`: no place and delete loop).
pub fn snapshot_rights(s: Seeds) -> Res<Report> {
    use osis_proto::LabelStore;
    use osis_schema::{History, PurgeBy, Retention};
    let (mut sim, (s, a, b, w, pa, pb, pw, g, t)) = setup("snapshot_rights", s, NetWeights::default(), |sim| {
        let mut d = Dice::new(sim.seed ^ 0x5a9);
        let s = sim.add_host()?;
        let a = sim.add_node(&[s], clock(&mut d))?;
        let b = sim.add_node(&[s], clock(&mut d))?;
        let w = sim.add_node(&[s], clock(&mut d))?;
        let [pa, pb, pw] = persons(sim, [a, b, w], [s, s, s])?;
        let g = shared_group(sim, a, pa, &[s], &[(pb, Role::Write), (pw, Role::Write)])?;
        let t = sim.item(a, g)?;
        sim.quiet(40)?;
        Ok((s, a, b, w, pa, pb, pw, g, t))
    })?;
    let mut d = Dice::new(sim.seed ^ 0x5a9);
    let by = PurgeBy::from_id(1 + d.below(3)).unwrap_or_default();
    // the thing's setting for the aspect (spec/commits.md §5 The setting): 0 no history promised;
    // 1 kept a while after replaced; 2 purge on replace
    let bound = d.below(3);
    let history = match bound {
        1 => Some(History::Keep { until: None, after: Some(1_800_000) }),
        2 => Some(History::PurgeOnReplace),
        _ => None,
    };
    let keep = Retention { by };
    let k = ak(&sim, &workload::REG)?;
    if let Some(h) = history {
        let mut m = Mutation::new();
        m.set(t, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(k.clone(), h)).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(a, m)?;
        sim.quiet(40)?;
    }
    // every node here writes: any writer's cover drops a replaced body out of history, the purge
    // right or not (spec/commits.md §5 Out of history), and at the end every body is out
    // two rounds of overwrites, each followed by the seed's compacters
    // (commit, author node, an explicit compaction followed, its value, its stamp)
    let mut written: Vec<(osis_base::CommitId, usize, bool, Value, osis_base::Ts)> = Vec::new();
    for round in 0..2 {
        for (i, (n, person)) in [(a, pa), (b, pb), (w, pw)].into_iter().cycle().take(6).enumerate() {
            let mut m = Mutation::new();
            // as the app writes: for the account, so any of its nodes holds the author's right
            m.act_as(person);
            m.retention(t, &workload::REG, keep).map_err(|e| sim.fail(e.to_string()))?;
            let v = Value::Str(format!("v{round}.{i}"));
            m.set(t, &workload::REG, &v).map_err(|e| sim.fail(e.to_string()))?;
            if let Some(c) = sim.commit(n, m)? {
                let ts = sim.engine(n)?.header(&c).ok_or_else(|| sim.fail("no header of an own write"))?.ts;
                written.push((c, n, false, v, ts));
            }
            sim.quiet(40)?;
        }
        for n in [a, b, w] {
            if d.below(2) == 0 {
                let acts = sim.sync(n)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("node {n} compact: {e}")))?;
                sim.actions(n, acts)?;
                sim.quiet(40)?;
                for x in written.iter_mut() {
                    x.2 = true;
                }
            }
        }
    }
    // past `MAX_DRIFT`: right holders have dropped what they may
    sim.advance(2 * 3_600_000)?;
    sim.quiet(40)?;
    sim.run_until_quiescent(60)?;
    let fresh = sim.add_node(&[s], clock(&mut d))?;
    sim.pair(b, fresh)?;
    sim.quiet(40)?;
    sim.run(40)?;
    // the author's other node compacts with its right; a body whose live write it lacks stays
    // uncovered, so what it may drop is not certain to go
    let fresh_compacted = d.below(2) == 0;
    if fresh_compacted {
        let acts = sim.sync(fresh)?.compact_now(&t, &k).map_err(|e| sim.fail(format!("fresh compact: {e}")))?;
        sim.actions(fresh, acts)?;
        sim.quiet(40)?;
    }
    sim.run_until_quiescent(60)?;
    let l = sim.sync(a)?.labels().into_iter().find(|x| x.0 == g).map(|x| x.1.id).ok_or_else(|| sim.fail("no label"))?;
    let live: BTreeSet<osis_base::BlobId> = sim.hub(s).ok_or_else(|| sim.fail("no hub"))?.store().live_ids(&l).map_err(|e| sim.fail(e.to_string()))?.into_iter().collect();
    let entries = sim.sync(a)?.entries(&l);
    let in_store = |c: &osis_base::CommitId| entries.iter().any(|(id, x)| live.contains(id) && matches!(x, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c));
    // the live write is the one read (values are unique; every node reads alike, checked below),
    // and a register write is covered by a snapshot whose winning write is stamped no earlier
    // (spec/commits.md §5 Covered: joining it changes nothing), whichever node wrote it, the
    // trigger or the scenario; a snapshot covering an earlier one wins no earlier, so the held
    // ones say
    let read = sim.engine(a)?.get_typed(&t, &workload::REG).ok().flatten();
    let mut snap_wins: Option<osis_base::Ts> = None;
    for n in [a, b, w, fresh] {
        let e = sim.engine(n)?;
        let ids: Vec<osis_base::CommitId> = e.core.ix.snapshots.get(&(t, k.clone())).into_iter().flatten().map(|x| x.1).collect();
        for x in ids {
            let f = e.body_fragment(&x, &t, &k).ok().flatten();
            snap_wins = snap_wins.max(f.and_then(|f| f.live_writes().into_iter().filter_map(|(_, ts)| ts).max()));
        }
    }
    for (c, author, explicit, v, ts) in &written {
        let is_live = read.as_ref() == Some(v);
        // the setting keeps a live body for good under a D (spec/commits.md §5 Kept while live),
        // none elsewhere
        let kept_live = is_live && bound == 1;
        let dead = bound == 2 && !is_live;
        // a snapshot covering it, or its author's own whole replaces (spec/commits.md §5 Own
        // replaces: two later writes of its author, scenario or random, fresh writing as b's device)
        let snapped = snap_wins >= Some(*ts);
        let later = sim.written.iter().skip_while(|x| x.1 != *c).skip(1).filter(|x| (if x.0 == fresh { b } else { x.0 }) == *author).count();
        let own = !is_live && later >= 2;
        // past every keep bound (the run waited out the history kept after replaced)
        let may_go = !kept_live && (snapped || own);
        // a writer's explicit compaction after it covers it at that writer, which drops and
        // deletes it (purge on replace: gone everywhere once replaced); a body kept a while after
        // replaced may wait for the next snapshot, so only what stays is certain there
        let gone = !kept_live && (*explicit || dead);
        if (gone && bound != 1 && in_store(c)) || (!may_go && !in_store(c)) {
            return Err(sim.fail(format!("{by:?} bound {bound}: body of node {author} (live {is_live}) at the host {}, may go {may_go}, should be gone {gone}", in_store(c))));
        }
        for n in [a, b, w, fresh] {
            let e = sim.engine(n)?;
            let m = e.core.ix.commits.get(c);
            let held = m.is_some_and(|m| m.view.aspects.iter().position(|x| x.tid == t && x.ak == k).is_some_and(|ai| !m.is_dropped(ai) && !m.missing(ai)));
            if !may_go && !held {
                return Err(sim.fail(format!("{by:?} bound {bound}: kept body of node {author} not held at node {n}")));
            }
            if dead && held {
                return Err(sim.fail(format!("{by:?}: replaced purge-on-replace body held at node {n}")));
            }
        }
    }
    let reads: Vec<Option<Value>> = [a, b, w, fresh].into_iter().map(|n| sim.engine(n).map(|e| e.get_typed(&t, &workload::REG).ok().flatten())).collect::<Res<_>>()?;
    if reads.windows(2).any(|x| x.first() != x.last()) {
        return Err(sim.fail(format!("{by:?}: reads differ: {reads:?}")));
    }
    sim.finish()
}

/// How the nodes of a peers-only scenario are placed.
#[derive(Clone, Copy, Debug)]
enum Topology {
    /// One LAN, no internet: announcements are the only way to find each other.
    Lan,
    /// Public addresses.
    Public,
    /// Symmetric NATs and a relay: everything relayed.
    Relayed,
    /// Cone NATs and a relay: punched.
    Punched,
}

/// Places nodes `ns` per `t`; each publishes its `reach.0`.
fn place_nodes(sim: &mut NetSim, ns: &[usize], t: Topology) -> Res<()> {
    let relay = matches!(t, Topology::Relayed | Topology::Punched).then(|| sim.reach.add_relay(None));
    let relays: Vec<usize> = relay.into_iter().collect();
    for n in ns {
        let uplink = match t {
            Topology::Lan => Uplink::None,
            Topology::Public => Uplink::Public,
            Topology::Relayed => Uplink::Nat(sim.reach.add_nat(osis_transport::nat::Nat::SYMMETRIC)),
            Topology::Punched => Uplink::Nat(sim.reach.add_nat(osis_transport::nat::Nat::CONE)),
        };
        let lans: &[u32] = if matches!(t, Topology::Lan) { &[1] } else { &[] };
        sim.reach.place(*n, lans, uplink, &relays);
    }
    Ok(())
}

/// Accounts on `ns` with no host, each listening; a group of the first's account granted to the
/// others. With no host there is no contact card (it needs one): each side hands the other
/// everything it holds over a direct connection (`NetSim::direct`), its node's `reach.0` and the
/// edges that make that node a reader among it.
pub fn peer_group(sim: &mut NetSim, ns: &[usize]) -> Res<Tid> {
    let mut persons = Vec::new();
    for n in ns {
        persons.push(sim.account(*n, &[])?.account);
        sim.listen_peer(*n)?;
    }
    let (Some(&a), Some(&pa)) = (ns.first(), persons.first()) else { return Err(sim.fail("no nodes")) };
    for n in ns.iter().skip(1) {
        sim.direct(*n, a)?;
    }
    let g = sim.group_with(a, pa, &[], true)?;
    for p in persons.iter().skip(1) {
        sim.grant(a, g, *p, Role::Write)?;
    }
    sim.item(a, g)?;
    for n in ns.iter().skip(1) {
        sim.direct(a, *n)?;
    }
    Ok(g)
}

/// spec/requirements.md (Decentralization), spec/sync.md §5, §10: holders with no host at all
/// sync a group over peer links, by the seed's topology (one LAN, public addresses, relayed behind
/// symmetric NATs, punched behind cone NATs), under link faults, partitions and crashes.
pub fn no_host(s: Seeds) -> Res<Report> {
    // the seed's topology: a setup of each
    let t = match Dice::new(s.seed ^ 0x9e).below(4) {
        0 => Topology::Lan,
        1 => Topology::Public,
        2 => Topology::Relayed,
        _ => Topology::Punched,
    };
    let weights = NetWeights { crash: 1, restart: 2, partition: 1, heal: 2, lan: 3, ..NetWeights::default() };
    let cfg = NetConfig { faults: lossy(), weights, ..NetConfig::default() };
    let (mut sim, ns) = NetSim::setup("no_host", &format!("{t:?}"), s, cfg, |sim| {
        let mut d = Dice::new(sim.seed ^ 0x9e);
        let ns = [sim.add_node(&[], clock(&mut d))?, sim.add_node(&[], clock(&mut d))?, sim.add_node(&[], clock(&mut d))?];
        sim.note(format!("topology {t:?}"));
        place_nodes(sim, &ns, t)?;
        peer_group(sim, &ns)?;
        sim.quiet(40)?;
        Ok(ns)
    })?;
    sim.run(150)?;
    sim.run_until_quiescent(40)?;
    peers_carry(&mut sim, &ns)?;
    sim.finish()
}

/// What the last of `ns` writes reaches the first over peer links alone: a run that synced
/// nothing fails here whatever its random steps did.
fn peers_carry(sim: &mut NetSim, ns: &[usize]) -> Res<()> {
    let (Some(&first), Some(&last), Some(g)) = (ns.first(), ns.last(), sim.groups.first().map(|g| g.g)) else { return Err(sim.fail("no nodes or group")) };
    let t = sim.item(last, g)?;
    sim.quiet(40)?;
    let k = ak(sim, &workload::REG)?;
    if sim.engine(first)?.get(&t, &k).ok().flatten().is_none() {
        return Err(sim.fail(format!("node {first} never read node {last}'s write")));
    }
    Ok(())
}

/// spec/requirements.md (Decentralization: through any willing node): holders on two LANs joined
/// only by a holder on both, with no host: what either end writes reaches the other through it.
pub fn no_host_chain(s: Seeds) -> Res<Report> {
    let weights = NetWeights { crash: 1, restart: 2, partition: 1, heal: 2, lan: 3, ..NetWeights::default() };
    let (mut sim, ns) = setup("no_host_chain", s, weights, |sim| {
        let mut d = Dice::new(sim.seed ^ 0xc4);
        let ns = [sim.add_node(&[], clock(&mut d))?, sim.add_node(&[], clock(&mut d))?, sim.add_node(&[], clock(&mut d))?];
        let [a, b, c] = ns;
        sim.reach.place(a, &[1], Uplink::None, &[]);
        sim.reach.place(b, &[1, 2], Uplink::None, &[]);
        sim.reach.place(c, &[2], Uplink::None, &[]);
        peer_group(sim, &ns)?;
        sim.quiet(40)?;
        Ok(ns)
    })?;
    sim.run(150)?;
    sim.run_until_quiescent(40)?;
    peers_carry(&mut sim, &ns)?;
    sim.finish()
}
