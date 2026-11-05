//! Phase C scenario library (notes/testing.md, Phase C; notes/permissions.md): the
//! named role and retention stories over sync engines and hosts. Each sets up with
//! flows, runs a faulty schedule around the story's critical moment, checks the story's expected
//! outcome, and ends with the quiescent invariants (`check`).

use super::scenarios::{DAY_MS, clock, newest_read, persons, shared_group, sim};
use super::{NetConfig, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use crate::workload;
use osis_base::{CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::Mutation;
use osis_node::flows::{Demotion, LinkSpec, PreSync};
use osis_node::sync::Event;
use osis_schema::core_types as ct;
use osis_schema::{Bound, PurgeBy, Retention};
use std::collections::BTreeSet;

const HOUR_MS: u64 = 3_600_000;

/// The story marks node `n` reads on `t` (`s:story.0`).
pub fn tags(sim: &mut NetSim, n: usize, t: Tid) -> Res<BTreeSet<String>> {
    let k = super::scenarios::ak(sim, &workload::STORY)?;
    let v = sim.engine(n)?.get(&t, &k).map_err(|e| sim.fail(format!("node {n} read: {e}")))?;
    let mut out = BTreeSet::new();
    if let Some(Value::Set(s)) = v {
        for x in s {
            if let Value::Str(w) = x {
                out.insert(w);
            }
        }
    }
    Ok(out)
}

/// Node `n` adds story mark `w` to `t`.
pub fn add_tag(sim: &mut NetSim, n: usize, t: Tid, w: &str) -> Res<CommitId> {
    let mut m = Mutation::new();
    m.op(t, &workload::STORY, PathOp { path: Vec::new(), op: Op::Add(Value::Str(w.into())) }).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))
}

/// Every node in `ns` reads exactly `want` among the story's tags `story` on `t`.
fn expect_tags(sim: &mut NetSim, ns: &[usize], t: Tid, story: &[&str], want: &[&str]) -> Res<()> {
    for &n in ns {
        let got: BTreeSet<String> = tags(sim, n, t)?.into_iter().filter(|w| story.contains(&w.as_str())).collect();
        let want: BTreeSet<String> = want.iter().map(|w| w.to_string()).collect();
        if got != want {
            return Err(sim.fail(format!("node {n} reads tags {got:?} on {t}, expected {want:?} (of {story:?})")));
        }
    }
    Ok(())
}

fn demote(sim: &mut NetSim, n: usize, target: Tid, holder: Tid, new: Option<Role>, presync: PreSync) -> Res<()> {
    let new = new.map(|role| ct::Edge { role, until: None, invite: None, since: None, tied: None });
    let r = sim.engine(n)?.demote(&target, &Demotion { holder, new, presync, keep: None });
    let done = r.map_err(|e| sim.fail(format!("node {n} demote: {e}")))?;
    sim.carry(n, done)
}

/// The revocation reference scenario (notes/permissions.md, Revocation; spec/permissions.md
/// §5.1, §5.2): Alice shares a doc with Bob; Bob goes offline and writes X; Alice removes Bob
/// without having seen X; Bob writes Y and comes back. X and Y are invalid everywhere. A re-grant
/// makes valid again those that reached another node: Bob forgets the doc once the removal
/// applies there (spec/permissions.md §3), his own copies too, and regains it by sync.
pub fn revocation_bob(seed: u64) -> Res<Report> {
    revocation("revocation_bob", seed, false)
}

/// The Carol variant: Carol, a writer offline with Bob, syncs with him directly; X is invalid
/// for her too once she learns of the removal; the re-grant restores X and Y.
pub fn revocation_carol(seed: u64) -> Res<Report> {
    revocation("revocation_carol", seed, true)
}

fn revocation(name: &str, seed: u64, carol: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xb0b);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pc, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    add_tag(&mut sim, b, t, "mon")?;
    sim.run(40)?;
    sim.quiet(40)?;
    // Tue: Bob (and Carol) offline
    sim.sever(Party::N(b), Party::S(s));
    if carol {
        sim.sever(Party::N(c), Party::S(s));
    }
    sim.advance(DAY_MS)?;
    add_tag(&mut sim, b, t, "x")?;
    sim.advance(DAY_MS)?;
    // Thu: Alice removes Bob without having seen X
    sim.remove(a, g, pb)?;
    sim.excused.insert(b);
    sim.run(30)?;
    sim.advance(DAY_MS)?;
    add_tag(&mut sim, b, t, "y")?;
    if carol {
        sim.direct(b, c)?;
        expect_tags(&mut sim, &[c], t, &["x", "y"], &["x", "y"])?;
    }
    sim.advance(DAY_MS)?;
    // Sun: they come back
    sim.unsever(Party::N(b), Party::S(s));
    sim.unsever(Party::N(c), Party::S(s));
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    expect_tags(&mut sim, &[a, c], t, &["mon", "x", "y"], &["mon"])?;
    // a re-grant validates the gap (§5.2): Carol held X and Y; without her, what Bob uploaded
    // before he forgot (all agree)
    sim.grant(a, g, pb, Role::Write)?;
    sim.excused.remove(&b);
    sim.run(40)?;
    sim.run_until_quiescent(60)?;
    let story = ["mon", "x", "y"];
    let want: Vec<String> = if carol { story.iter().map(|w| w.to_string()).collect() } else { tags(&mut sim, a, t)?.into_iter().filter(|w| story.contains(&w.as_str())).collect() };
    let want: Vec<&str> = want.iter().map(String::as_str).collect();
    if !want.contains(&"mon") {
        return Err(sim.fail(format!("the re-grant lost Monday's edit: {want:?}")));
    }
    expect_tags(&mut sim, &[a, b, c], t, &story, &want)?;
    sim.finish()
}

/// A stolen device backdates (notes/permissions.md, Revocation; spec/permissions.md §5.1, §5.3):
/// the thief winds its clock back and writes; the honest device removes it with a revoke
/// backdated to the theft, so the forged edit is dropped everywhere and the device's honest edits
/// before the theft stay.
pub fn stolen_device(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x57);
    let mut sim = sim("stolen_device", seed, NetWeights::default());
    let s = sim.add_host()?;
    let d0 = sim.add_node(&[s], clock(&mut d))?;
    let d1 = sim.add_node(&[s], clock(&mut d))?;
    let p = sim.person(d1, &[s])?.person;
    sim.pair(d1, d0, p)?;
    let u = sim.item(d1, p)?;
    sim.quiet(40)?;
    add_tag(&mut sim, d0, u, "honest")?;
    sim.run(40)?;
    sim.quiet(40)?;
    let theft = sim.engine(d0)?.now();
    sim.excused.insert(d0);
    sim.advance(2 * HOUR_MS)?;
    // the thief winds its clock back to just after the theft and writes
    let skew = sim.nodes.get(d0).map(|x| x.spec.skew_ms).unwrap_or(0);
    sim.set_skew(d0, skew - 2 * HOUR_MS as i64 + 60_000)?;
    add_tag(&mut sim, d0, u, "forged")?;
    sim.run(30)?;
    sim.quiet(40)?;
    if !tags(&mut sim, d1, u)?.contains("forged") {
        return Err(sim.fail("the honest device never received the forged edit"));
    }
    let backdated = PreSync::Backdated(WallMs(theft.0 + HOUR_MS / 2));
    let dt = sim.tid(d0)?;
    demote(&mut sim, d1, p, dt, None, backdated)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    expect_tags(&mut sim, &[d1], u, &["honest", "forged"], &["honest"])?;
    if sim.engine(d1)?.roster(&p).contains_key(&dt) {
        return Err(sim.fail("the stolen device is still on the person's roster"));
    }
    sim.finish()
}

/// Demotion to read with the pre-sync (spec/permissions.md §5.3): the writer's edits reached the
/// host before the demotion; the admin syncs first, so its frontier covers them and they stay.
pub fn demotion_synced(seed: u64) -> Res<Report> {
    demotion("demotion_synced", seed, true)
}

/// Demotion without the pre-sync (spec/permissions.md §5.3): the writer's last edit has not
/// reached the admin, which stamps anyway (`Unsynced { proceed }`): that edit is lost everywhere,
/// the earlier ones stay; the demoted holder still reads.
pub fn demotion_unsynced(seed: u64) -> Res<Report> {
    demotion("demotion_unsynced", seed, false)
}

fn demotion(name: &str, seed: u64, synced: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xde);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    add_tag(&mut sim, b, t, "early")?;
    sim.run(40)?;
    sim.quiet(40)?;
    if synced {
        add_tag(&mut sim, b, t, "late")?;
        sim.run(30)?;
        // the pre-sync: the admin downloads before stamping
        sim.quiet(40)?;
        if !tags(&mut sim, a, t)?.contains("late") {
            return Err(sim.fail("the pre-sync did not bring the late edit"));
        }
        demote(&mut sim, a, g, pb, Some(Role::Read), PreSync::Synced)?;
    } else {
        // the admin cannot reach the host; the late edit sits there
        sim.sever(Party::N(a), Party::S(s));
        add_tag(&mut sim, b, t, "late")?;
        sim.run(30)?;
        sim.advance(60_000)?;
        demote(&mut sim, a, g, pb, Some(Role::Read), PreSync::Unsynced { proceed: true })?;
        sim.unsever(Party::N(a), Party::S(s));
    }
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    let want: &[&str] = if synced { &["early", "late"] } else { &["early"] };
    expect_tags(&mut sim, &[a, b], t, &["early", "late"], want)?;
    if sim.engine(b)?.role_on(&t) != Some(Role::Read) {
        return Err(sim.fail("the demoted holder does not read"));
    }
    sim.finish()
}

/// A demotion from a node holding part of the tree (notes/sync.md Receipts-only reads;
/// spec/permissions.md §5.1, §5.3): Alice's phone holds her group G but holds its subgroup H for
/// receipts only. Bob writes under both; the phone, alone with the host, reads H's commit
/// headers and removes Bob: H's log there does not move (the phone uploads, deletes and places
/// nothing under it), and Bob's edit under H, which the phone never held, stays everywhere.
pub fn demotion_receipts(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x4ec);
    let mut sim = sim("demotion_receipts", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pc, Role::Write)])?;
    let h = sim.group(a, g, &[s])?;
    let t = sim.item(a, g)?;
    let u = sim.item(a, h)?;
    // random writes stay within G: a commit spanning G and H is one blob under both, and the
    // phone would wait for H's item's creation record (issues/revoke-needs-whole-tree.md)
    sim.groups.retain(|x| x.g != h);
    sim.quiet(40)?;
    let phone = sim.add_node(&[s], clock(&mut d))?;
    let acts = sim.sync(phone)?.set_receipts_only(h, true);
    sim.actions(phone, acts)?;
    sim.pair(a, phone, pa)?;
    sim.quiet(40)?;
    add_tag(&mut sim, b, t, "in g")?;
    add_tag(&mut sim, b, u, "in h")?;
    sim.run(40)?;
    sim.quiet(40)?;
    if !sim.engine(phone)?.knows(&t) || sim.engine(phone)?.knows(&u) {
        return Err(sim.fail("the phone should hold G's item and none of H's"));
    }
    // the phone alone with the host
    for n in [a, b, c] {
        sim.sever(Party::N(n), Party::S(s));
    }
    let label = sim.engine(a)?.group_labels(&h).map_err(|e| sim.fail(e.to_string()))?.first().map(|l| l.id).ok_or_else(|| sim.fail("H has no label"))?;
    let log = |sim: &NetSim| sim.hub(s).map(|x| osis_proto::store::LabelStore::log_head(x.store(), &label).ok());
    let before = log(&sim);
    let acts = sim.sync(phone)?.read_receipts(&[h]);
    sim.actions(phone, acts)?;
    let mut read = None;
    for _ in 0..1000 {
        sim.run(5)?;
        read = sim.sync(phone)?.receipts_read(&[h]);
        if read.is_some() {
            break;
        }
    }
    if read != Some(Ok(())) {
        return Err(sim.fail(format!("the receipts-only read of H did not finish: {read:?}")));
    }
    sim.sync(phone)?.end_receipts(&[h]);
    demote(&mut sim, phone, g, pb, None, PreSync::Synced)?;
    sim.run(30)?;
    if log(&sim) != before {
        return Err(sim.fail("the phone wrote under H's label"));
    }
    sim.excused.insert(b);
    for n in [a, b, c] {
        sim.unsever(Party::N(n), Party::S(s));
    }
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    expect_tags(&mut sim, &[a, c, phone], t, &["in g"], &["in g"])?;
    expect_tags(&mut sim, &[a, c], u, &["in h"], &["in h"])?;
    if sim.engine(a)?.roster(&g).contains_key(&pb) {
        return Err(sim.fail("Bob is still on G's roster"));
    }
    sim.finish()
}

/// A person on node `n` follows a link's label and redeems it (spec/permissions.md §8), as the
/// osis crate does: hold L, follow K's label, wait, redeem, drop L. Err when the redemption is
/// refused (a used single-use link).
fn redeem(sim: &mut NetSim, n: usize, link: &osis_label::ShareLink, person: Tid) -> Res<Result<(), String>> {
    let l = sim.engine(n)?.hold_key_actor(link.seed.clone()).map_err(|e| sim.fail(e.to_string()))?;
    let acts = sim.sync(n)?.follow(l, link.k, link.k_label, link.hosts.clone());
    sim.actions(n, acts)?;
    sim.quiet(40)?;
    let r = sim.engine(n)?.redeem(link, &person, link.single_use);
    sim.engine(n)?.drop_key_actor(&l);
    match r {
        Ok(done) => {
            sim.carry(n, done)?;
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e.to_string())),
    }
}

/// Link redemption race and single use (spec/permissions.md §8, §5.1): two strangers redeem one
/// single-use link concurrently; the sharer and the winner agree on exactly one joiner (the
/// first by the timeline's order; the loser, rotated out of K, may not learn it); the sharer
/// finalizes; a third redeemer is refused.
pub fn link_race(seed: u64) -> Res<Report> {
    links("link_race", seed, true)
}

/// Concurrent redemptions of a multi-use link (spec/permissions.md §8): both strangers join and
/// read the target; the sharer then revokes the link (removes L); a later redeemer is refused.
pub fn link_redeem(seed: u64) -> Res<Report> {
    links("link_redeem", seed, false)
}

fn links(name: &str, seed: u64, single_use: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x11);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let x = sim.add_node(&[s], clock(&mut d))?;
    let y = sim.add_node(&[s], clock(&mut d))?;
    let z = sim.add_node(&[s], clock(&mut d))?;
    let [pa, px, py, pz] = persons(&mut sim, [a, x, y, z], [s, s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    let spec = LinkSpec { target: g, role: Role::Read, until: None, hosts: sim.addresses(&[s]), peers: Vec::new(), single_use };
    let r = sim.engine(a)?.create_link(&pa, &spec);
    let (link, _, done) = r.map_err(|e| sim.fail(format!("create_link: {e}")))?;
    sim.carry(a, done)?;
    sim.quiet(40)?;
    let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
    // both follow K's label, then redeem before either sees the other
    for n in [x, y] {
        let held = sim.engine(n)?.hold_key_actor(link.seed.clone()).map_err(|e| sim.fail(e.to_string()))?;
        let acts = sim.sync(n)?.follow(held, link.k, link.k_label, link.hosts.clone());
        sim.actions(n, acts)?;
    }
    sim.quiet(40)?;
    let mut dones = Vec::new();
    for (n, p) in [(x, px), (y, py)] {
        let r = sim.engine(n)?.redeem(&link, &p, single_use);
        dones.push((n, r.map_err(|e| sim.fail(format!("node {n} redeem: {e}")))?));
    }
    for (n, done) in dones {
        sim.engine(n)?.drop_key_actor(&l);
        sim.carry(n, done)?;
    }
    sim.run(60)?;
    if single_use {
        // the loser's grant is invalid (L left before it); once K rotates without it, it reads
        // nothing more of K and may keep its own view of the race (spec/permissions.md §5.1)
        sim.quiet(40)?;
        let r = sim.engine(a)?.roster(&link.k);
        for (n, p) in [(x, px), (y, py)] {
            if !r.contains_key(&p) {
                sim.excused.insert(n);
            }
        }
    }
    sim.run_until_quiescent(40)?;
    let mut joined = None;
    for n in [a, x, y] {
        if sim.excused.contains(&n) {
            continue;
        }
        let r = sim.engine(n)?.roster(&link.k);
        let who: Vec<Tid> = [px, py].into_iter().filter(|p| r.contains_key(p)).collect();
        let want = if single_use { 1 } else { 2 };
        if who.len() != want || r.contains_key(&l) == single_use {
            return Err(sim.fail(format!("node {n}: K's roster after the race lists {who:?} of the redeemers, link key {}", r.contains_key(&l))));
        }
        if joined.as_ref().is_some_and(|j| *j != who) {
            return Err(sim.fail("nodes disagree on who redeemed the link"));
        }
        joined = Some(who);
    }
    if single_use {
        let (winner, loser) = if joined.is_some_and(|j| j.contains(&px)) { (x, y) } else { (y, x) };
        if sim.engine(winner)?.role_on(&g).is_none_or(|r| r < Role::Read) || !sim.excused.contains(&loser) {
            return Err(sim.fail("the winner does not read the target, or the loser is on K's roster"));
        }
    } else {
        for n in [x, y] {
            if sim.engine(n)?.role_on(&g).is_none_or(|r| r < Role::Read) {
                return Err(sim.fail(format!("redeemer node {n} does not read the target")));
            }
        }
    }
    // the sharer finalizes (single use) or revokes the link; a later redeemer is refused
    let r = sim.engine(a)?.finalize_link(&link.k, &l);
    let done = r.map_err(|e| sim.fail(format!("finalize_link: {e}")))?;
    sim.carry(a, done)?;
    sim.quiet(40)?;
    if redeem(&mut sim, z, &link, pz)?.is_ok() {
        sim.quiet(40)?;
        if sim.engine(a)?.roster(&link.k).contains_key(&pz) {
            return Err(sim.fail("a finalized link admitted a later redeemer"));
        }
    }
    sim.excused.insert(z);
    sim.run(30)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Group join and leave in the old persona shape: chat actor C with its own label, participants
/// writers of C; each joins with a persona P owned by its person (secrets of its own), C made a
/// reader of P, P listed in C's items and subgroups; messages are things owned by P in P's `group.0`. A
/// participant is removed: C rotates; it holds no later epoch, the others keep posting and
/// converge.
pub fn chat_join_leave(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc4);
    let mut sim = sim("chat_join_leave", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s, s, s])?;
    let chat = sim.group_with(a, pa, &[s], true)?;
    sim.quiet(40)?;
    for p in [pb, pc] {
        sim.grant(a, chat, p, Role::Write)?;
        sim.quiet(40)?;
    }
    sim.reconnect_all();
    sim.quiet(40)?;
    // each participant joins: a persona with secrets of its own, C reads it, listed in C
    let mut personas = Vec::new();
    for (n, p) in [(a, pa), (b, pb), (c, pc)] {
        let persona = persona(&mut sim, n, p, chat)?;
        personas.push((n, persona));
        sim.quiet(40)?;
    }
    for (n, persona) in personas.clone() {
        message(&mut sim, n, persona, "hello")?;
    }
    sim.run(80)?;
    sim.quiet(60)?;
    let before = newest_read(&mut sim, a, &chat)?;
    // C is removed from the chat (its person; its persona stays its own)
    sim.remove(a, chat, pc)?;
    sim.excused.insert(c);
    for (n, persona) in personas.clone() {
        if n != c {
            message(&mut sim, n, persona, "after")?;
        }
    }
    sim.run(80)?;
    sim.run_until_quiescent(60)?;
    // C forgets what it lost once the removal applies there (spec/permissions.md §3): the chat
    // and the others' personas, not its own
    if sim.engine(c)?.role_on(&chat).is_none() {
        for (n, persona) in personas.clone() {
            let held = sim.engine(c)?.get_typed(&persona, &ct::GROUP).map_err(|e| sim.fail(e.to_string()))?.is_some();
            if held != (n == c) {
                return Err(sim.fail(format!("C after dropping: persona of node {n} held: {held}")));
            }
        }
        sim.run(40)?;
        sim.run_until_quiescent(60)?;
    }
    let now = newest_read(&mut sim, a, &chat)?;
    if now == before {
        return Err(sim.fail("the removal did not rotate the chat"));
    }
    if newest_read(&mut sim, c, &chat)?.is_some_and(|x| Some(x) >= now) {
        return Err(sim.fail("the removed participant holds the chat's new epoch"));
    }
    if newest_read(&mut sim, b, &chat)? != now {
        return Err(sim.fail("a remaining participant does not hold the chat's new epoch"));
    }
    sim.finish()
}

/// A persona of person `p` on node `n` for chat `chat`.
pub fn persona(sim: &mut NetSim, n: usize, p: Tid, chat: Tid) -> Res<Tid> {
    let e = sim.engine(n)?;
    let mut m = Mutation::new();
    let persona = e.new_thing(&mut m, p);
    m.set(persona, &ct::GROUP, &ct::Group::default()).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    let r = sim.engine(n)?.give_own_secrets(&persona);
    let done = r.map_err(|e| sim.fail(format!("node {n} persona secrets: {e}")))?;
    sim.carry(n, done)?;
    sim.grant(n, persona, chat, Role::Read)?;
    // an item too: the persona's own writes (`created.0`, `group.0`, secrets) are in C's closure
    // only as a member (spec/data-model.md §8: members are items and the subgroups' members)
    let mut grp = sim.engine(n)?.get_typed(&chat, &ct::GROUP).map_err(|e| sim.fail(e.to_string()))?.unwrap_or_default();
    grp.items.insert(persona);
    grp.subgroups.insert(persona);
    let mut m = Mutation::new();
    m.set(chat, &ct::GROUP, &grp).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(n, m)?;
    sim.groups.push(super::Group { g: persona, owner: p, items: Vec::new() });
    Ok(persona)
}

/// A chat message: a thing owned by the persona, placed in its `group.0`.
pub fn message(sim: &mut NetSim, n: usize, persona: Tid, text: &str) -> Res<Tid> {
    sim.item(n, persona).and_then(|t| {
        let mut m = Mutation::new();
        m.set(t, &workload::REG, &Value::Str(text.into())).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(n, m)?;
        Ok(t)
    })
}

/// Folder patterns (notes/permissions.md, Patterns: folder with rights): a folder actor owns its
/// things and a subfolder; the folder is shared with B (write), the subfolder alone with C (read,
/// its own secrets and label). B writes in both; C reads the subfolder and nothing of the
/// folder's own items.
pub fn folders(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xf0);
    let mut sim = sim("folders", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s, s, s])?;
    let folder = sim.group_with(a, pa, &[s], true)?;
    sim.quiet(40)?;
    let top = sim.item(a, folder)?;
    let sub = sim.group_with(a, folder, &[s], true)?;
    let inner = sim.item(a, sub)?;
    let mut grp = sim.engine(a)?.get_typed(&folder, &ct::GROUP).map_err(|e| sim.fail(e.to_string()))?.unwrap_or_default();
    grp.subgroups.insert(sub);
    let mut m = Mutation::new();
    m.set(folder, &ct::GROUP, &grp).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(a, m)?;
    sim.quiet(40)?;
    sim.grant(a, folder, pb, Role::Write)?;
    sim.quiet(40)?;
    sim.grant(a, sub, pc, Role::Read)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    add_tag(&mut sim, b, top, "top")?;
    add_tag(&mut sim, b, inner, "inner")?;
    sim.run(100)?;
    sim.run_until_quiescent(60)?;
    expect_tags(&mut sim, &[a, b], top, &["top"], &["top"])?;
    expect_tags(&mut sim, &[a, b, c], inner, &["inner"], &["inner"])?;
    if sim.engine(c)?.role_on(&top).is_some() || sim.engine(c)?.knows(&top) && !tags(&mut sim, c, top)?.is_empty() {
        return Err(sim.fail("the subfolder's reader reads the folder's own items"));
    }
    sim.finish()
}

/// Label replacement (spec/sync.md §2): the admin replaces a group's label; holders follow the
/// new label and converge. (Old-label cleanup is checked by `label_replacement_offline`.)
pub fn label_replacement(seed: u64) -> Res<Report> {
    replacement("label_replacement", seed, false)
}

/// Label replacement with a holder offline (spec/sync.md §2: the replacement `label.0` commit
/// stays under the old label, whose content entries the admin deletes, so a node that knows only
/// the old label finds the new one).
pub fn label_replacement_offline(seed: u64) -> Res<Report> {
    replacement("label_replacement_offline", seed, true)
}

fn replacement(name: &str, seed: u64, offline: bool) -> Res<Report> {
    use osis_proto::LabelStore;
    let mut d = Dice::new(seed ^ 0x1a);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    sim.run(40)?;
    sim.quiet(40)?;
    sim.observe()?;
    if offline {
        sim.node_down(b)?;
    }
    let old = sim.sync(a)?.labels().into_iter().find(|(t, _)| *t == g).map(|x| x.1.id).ok_or_else(|| sim.fail("no label"))?;
    let r = sim.sync(a)?.replace_label(&g, &old);
    let (new, acts) = r.map_err(|e| sim.fail(format!("replace_label: {e}")))?;
    sim.actions(a, acts)?;
    sim.run(60)?;
    sim.run_until_quiescent(60)?;
    let bl: Vec<_> = sim.sync(b)?.labels().into_iter().filter(|(t, _)| *t == g).map(|x| x.1.id).collect();
    if !bl.contains(&new) {
        return Err(sim.fail(format!("the holder does not follow the replacement label: {bl:?}")));
    }
    if offline {
        // the old label keeps role-class commits and certificates (chain certificates,
        // node cards, heartbeats: they verify what stays, spec/permissions.md §4) only
        let live = sim.hub(s).map(|h| h.store().live_ids(&old).unwrap_or_default()).unwrap_or_default();
        let kept = |ak: &str| ct::is_role_class(ak) || matches!(ak, "created.0" | "node.0" | "reach.0" | "seen.0" | "keys.0");
        let mut content = 0;
        for ((l, b), (c, parts)) in &sim.known {
            if *l != old || !live.contains(b) {
                continue;
            }
            let Some(h) = sim.nodes.iter().find_map(|n| n.sync.as_ref().and_then(|x| x.engine().header(c))) else { continue };
            if parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| !kept(a.ak.as_str())) {
                content += 1;
            }
        }
        if content > 0 {
            return Err(sim.fail(format!("the replaced label still holds {content} content entries ({} live)", live.len())));
        }
    }
    sim.finish()
}

/// Bundles by hand (spec/sync.md §8): a holder cut off from every host gets the group's label
/// as a bundle exported by the admin and reads what the admin reads; later online, it converges.
pub fn bundles(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xbd);
    let mut sim = sim("bundles", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Read)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    sim.sever(Party::N(b), Party::S(s));
    for w in ["one", "two", "three"] {
        add_tag(&mut sim, a, t, w)?;
    }
    sim.run(40)?;
    sim.quiet(40)?;
    let labels: Vec<_> = sim.sync(a)?.labels().into_iter().filter(|(x, _)| *x == g).map(|x| x.1.id).collect();
    let r = sim.sync(a)?.export_bundle(&labels);
    let bundle = r.map_err(|e| sim.fail(format!("export_bundle: {e}")))?;
    let r = sim.sync(b)?.import_bundle(&bundle);
    let acts = r.map_err(|e| sim.fail(format!("import_bundle: {e}")))?;
    sim.actions(b, acts)?;
    sim.feed(b, Event::Local)?;
    sim.quiet(20)?;
    expect_tags(&mut sim, &[b], t, &["one", "two", "three"], &["one", "two", "three"])?;
    sim.unsever(Party::N(b), Party::S(s));
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Expiry races and disappearing messages (spec/commits.md §5): holders post
/// messages (a thing with an expiring note, its placement expiring too) under a lossy network
/// with crashes while time passes; after the expiry no honest node reads an expired note and no
/// host holds a blob of one.
pub fn disappearing(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xd5);
    let mut sim = sim("disappearing", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    let mut notes = Vec::new();
    for k in 0..6u64 {
        let n = if k % 2 == 0 { a } else { b };
        if !sim.is_up(n) {
            sim.restart_node(n)?;
        }
        let life = (10 + d.below(20)) * 60_000;
        let at = sim.engine(n)?.now().0 + life;
        let e = sim.engine(n)?;
        // a crash mid-write loses the message, which is fine; the record and the expiring note
        // are two commits (spec/commits.md §6)
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, g);
        m.persist(t);
        if sim.write(n, m)?.is_empty() {
            continue;
        }
        let mut m = Mutation::new();
        m.set(t, &workload::NOTE, &Value::Str(format!("m{k}"))).map_err(|e| sim.fail(e.to_string()))?;
        m.expires(t, &workload::NOTE, WallMs(at)).map_err(|e| sim.fail(e.to_string()))?;
        if let Some(c) = sim.write(n, m)?.last() {
            notes.push((t, *c));
        }
        sim.run(25)?;
    }
    sim.run(40)?;
    sim.advance(HOUR_MS)?;
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    let nk = super::scenarios::ak(&sim, &workload::NOTE)?;
    for n in [a, b] {
        for (t, _) in &notes {
            let v = sim.engine(n)?.get(t, &nk).map_err(|e| sim.fail(e.to_string()))?;
            if v.is_some() {
                let wake = sim.nodes.get(n).and_then(|x| x.wake_at());
                return Err(sim.fail(format!("node {n} still reads the expired note on {t}: {v:?} (wake {wake:?})")));
            }
        }
    }
    expired_absent(&mut sim, &notes.iter().map(|x| x.1).collect::<Vec<_>>(), &nk)?;
    sim.finish()
}

/// No up host holds a live entry, and no honest node a blob, of the `ak` bodies of `commits`.
fn expired_absent(sim: &mut NetSim, commits: &[CommitId], ak: &osis_base::Ak) -> Res<()> {
    use osis_proto::LabelStore;
    let known = sim.known.clone();
    for ((l, b), (c, parts)) in known {
        if !commits.contains(&c) {
            continue;
        }
        let h = sim.nodes.iter().find_map(|n| n.sync.as_ref().and_then(|s| s.engine().header(&c)));
        let Some(h) = h else { continue };
        if !parts.iter().all(|(ai, _)| h.aspects.get(*ai).is_some_and(|x| x.ak == *ak)) {
            continue;
        }
        for s in 0..sim.hosts.len() {
            if sim.hub(s).is_some_and(|x| x.store().live_ids(&l).unwrap_or_default().contains(&b)) {
                let meta = sim.hub(s).and_then(|x| x.store().entry(&l, &b).ok().flatten()).map(|m| (m.stamp.is_some(), m.pending_delete));
                let key = sim.hosts.get(s).map(|x| x.key).unwrap_or_default();
                let mut views = Vec::new();
                for n in 0..sim.nodes.len() {
                    let Some(sy) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { continue };
                    let e = sy.entries(&l).into_iter().find(|x| x.0 == b).map(|x| format!("{:?}", x.1));
                    let v = sy.verdicts(&key, &l).ok().flatten().map(|v| (v.writer, v.must_not.iter().find(|x| x.0 == b).map(|x| x.1.clone()), v.must_hold.iter().any(|x| x.0 == c)));
                    let held = h.aspects.first().is_some_and(|x| sy.engine().body_not_dropped(&c, &x.tid, ak));
                    views.push(format!("node {n}: entry {e:?} (writer, must-not, must-hold) {v:?} holds body {held}"));
                }
                return Err(sim.fail(format!("host {s} still holds the expired body {b:?} of {c:?} (stamped, pending delete) {meta:?}; {views:?}")));
            }
        }
        for n in 0..sim.nodes.len() {
            if sim.excused.contains(&n) {
                continue;
            }
            if sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()).is_some_and(|s| s.holds_blob(&b)) {
                let e = sim.nodes.get(n).and_then(|x| x.sync.as_ref()).and_then(|s| s.entries(&l).into_iter().find(|x| x.0 == b)).map(|x| format!("{:?}", x.1));
                let parts = sim.engine(n)?.header(&c).map(|h| h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>());
                return Err(sim.fail(format!("node {n} still holds the expired body {b:?} of {c:?} (entry {e:?}, header aspects {parts:?})")));
            }
        }
    }
    Ok(())
}

/// Keep-at-most races (spec/commits.md §5): two writers overwrite an aspect kept at most 0 after
/// replaced, under a lossy network; an hour later every replaced body is gone from the host and
/// from honest nodes, the current value stays.
pub fn keep_at_most(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x4a);
    let mut sim = sim("keep_at_most", seed, NetWeights::default());
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    let mut written = Vec::new();
    for k in 0..8u32 {
        let n = if d.pct(50) { a } else { b };
        let mut m = Mutation::new();
        m.set(t, &workload::LATEST, &Value::Str(format!("v{k}"))).map_err(|e| sim.fail(e.to_string()))?;
        written.push(sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))?);
        sim.run(20)?;
    }
    sim.run(30)?;
    sim.quiet(40)?;
    sim.advance(HOUR_MS)?;
    sim.run(20)?;
    sim.run_until_quiescent(40)?;
    let k = super::scenarios::ak(&sim, &workload::LATEST)?;
    let v = sim.engine(a)?.get(&t, &k).map_err(|e| sim.fail(e.to_string()))?;
    if v.is_none() {
        return Err(sim.fail("the current value of a keep-at-most aspect is gone"));
    }
    // the replaced bodies: every written commit but the winner; the bodies each node holds
    let mut winners = BTreeSet::new();
    let mut held = Vec::new();
    for n in [a, b] {
        let e = sim.engine(n)?;
        let h: Vec<usize> = (0..written.len()).filter(|i| written.get(*i).is_some_and(|c| e.body_not_dropped(c, &t, &k))).collect();
        winners.extend(h.iter().filter_map(|i| written.get(*i).copied()));
        held.push(h);
    }
    let replaced: Vec<CommitId> = written.iter().filter(|c| !winners.contains(c)).copied().collect();
    if winners.len() > 1 {
        let now = sim.engine(a)?.now().0;
        let wake = sim.nodes.get(a).and_then(|x| x.wake_at());
        let mut deaths = Vec::new();
        for c in &written {
            deaths.push(sim.engine(a)?.deaths(c, &t, &k).ok().flatten().map(|x| x.0.wall_ms().0));
        }
        return Err(sim.fail(format!("replaced bodies kept past the keep-at-most bound: nodes hold writes {held:?} of {} (one is current); node {a} at {now}, wake {wake:?}, first deaths {deaths:?}", written.len())));
    }
    if replaced.is_empty() {
        return Err(sim.fail("nothing was replaced"));
    }
    expired_absent(&mut sim, &replaced, &k)?;
    sim.finish()
}

/// Lasting tombstones under churn (spec/commits.md §5, spec/sync.md §6): a writer's and an admin's
/// permanent messages, some purged by their author or an admin, one aspect-wide request by a writer
/// with no right over the rest, the host's data lost midway, and a device down through it all: it
/// sees each purged message as a tombstone with a purge that had the right and every other as a
/// body, and all that is left at the holders agrees.
pub fn purge_tombstones(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7b);
    let mut sim = sim("purge_tombstones", seed, NetWeights { crash: 0, restart: 0, ..NetWeights::default() });
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let e = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pe] = persons(&mut sim, [a, b, e], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pe, Role::Read)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    sim.node_down(e)?;
    let k = super::scenarios::ak(&sim, &workload::NOTE)?;
    let forever = Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(osis_commit::FOREVER), rel: None }, at_most: Bound::default() };
    let mut messages = Vec::new();
    let mut purged = BTreeSet::new();
    let mut said = 0u32;
    for round in 0..12u32 {
        said += 1;
        let n = if d.pct(50) { a } else { b };
        let mut m = Mutation::new();
        m.retention(t, &workload::NOTE, forever).map_err(|x| sim.fail(x.to_string()))?;
        m.set(t, &workload::NOTE, &Value::Str(format!("message {said}"))).map_err(|x| sim.fail(x.to_string()))?;
        let c = sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))?;
        messages.push((c, n));
        sim.run(10)?;
        if round == 6 {
            sim.wipe_host(s)?;
            sim.run(20)?;
        }
        if round == 9 {
            sim.node_down(b)?;
            sim.restart_node(b)?;
            sim.reconnect_all();
            sim.run(10)?;
        }
        if d.pct(40) {
            sim.quiet(40)?;
            let Some(&(c, author)) = messages.get(d.below(messages.len() as u64) as usize) else { continue };
            said += 1;
            // the author, or admin `a`, which holds the message by now
            let by = if d.pct(50) { author } else { a };
            let mut m = Mutation::new();
            m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
            m.set(t, &workload::NOTE, &Value::Str(format!("message {said}"))).map_err(|x| sim.fail(x.to_string()))?;
            if sim.commit(by, m)?.is_some() {
                purged.insert(c);
            }
            sim.run(10)?;
        }
    }
    // a writer's aspect-wide request: its own messages, none of the admin's
    sim.quiet(40)?;
    said += 1;
    let mut m = Mutation::new();
    m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: k.clone() });
    m.set(t, &workload::NOTE, &Value::Str(format!("message {said}"))).map_err(|x| sim.fail(x.to_string()))?;
    sim.commit(b, m)?;
    purged.extend(messages.iter().filter(|x| x.1 == b).map(|x| x.0));
    sim.run(20)?;
    sim.quiet(40)?;
    sim.restart_node(e)?;
    sim.reconnect_all();
    sim.run(30)?;
    sim.run_until_quiescent(40)?;
    let holders = sim.engine(a)?.purged_on(&t, &k).map_err(|x| sim.fail(x.to_string()))?;
    for n in [a, b, e] {
        let on = sim.engine(n)?.purged_on(&t, &k).map_err(|x| sim.fail(x.to_string()))?;
        if on != holders {
            return Err(sim.fail(format!("node {n} shows other purges: {on:?} against {holders:?}")));
        }
        for (c, author) in &messages {
            let (held, applied) = {
                let en = sim.engine(n)?;
                (en.body_not_dropped(c, &t, &k), en.commit_ids().contains(c))
            };
            let tomb = purged.contains(c);
            if tomb && held {
                return Err(sim.fail(format!("node {n}: purged message {c:?} of node {author} still held")));
            }
            if !applied || (tomb && !on.contains_key(c)) {
                return Err(sim.fail(format!("node {n}: message {c:?} (purged {tomb}) applied {applied}, shown {}", on.contains_key(c))));
            }
        }
    }
    sim.finish()
}

/// A purge that falls through a host (spec/permissions.md §7): admin `a` is cut off holding a
/// permanent message and removes admin `x`; `x`, not knowing, purges it (the seed: stamped before or
/// after the removal); the others drop the body and it goes from the host. `a` comes back: every
/// node left takes the body again and shows no purge, and nobody deletes it again (`sim.finish`
/// fails on a loop).
pub fn purge_falls(seed: u64) -> Res<Report> {
    purge_falls_how("purge_falls", seed, false)
}

/// `purge_falls` with nodes and the host crashing and restarting while it falls.
pub fn purge_falls_churn(seed: u64) -> Res<Report> {
    purge_falls_how("purge_falls_churn", seed, true)
}

fn purge_falls_how(name: &str, seed: u64, churn: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7c);
    let mut sim = sim(name, seed, NetWeights { crash: 0, restart: 0, partition: 0, heal: 0, ..NetWeights::default() });
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let x = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, px, pb] = persons(&mut sim, [a, x, b], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(px, Role::Admin), (pb, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.quiet(40)?;
    let k = super::scenarios::ak(&sim, &workload::NOTE)?;
    let forever = Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(osis_commit::FOREVER), rel: None }, at_most: Bound::default() };
    let mut m = Mutation::new();
    m.retention(t, &workload::NOTE, forever).map_err(|e| sim.fail(e.to_string()))?;
    m.set(t, &workload::NOTE, &Value::Str("kept".into())).map_err(|e| sim.fail(e.to_string()))?;
    let c = sim.commit(b, m)?.ok_or_else(|| sim.fail("wrote nothing"))?;
    sim.quiet(40)?;
    use super::Party::{N, S};
    let cut = [(N(a), S(s)), (N(a), N(b)), (N(a), N(x))];
    for (p, q) in cut {
        sim.partition(p, q);
    }
    let purge = |sim: &mut NetSim| -> Res<()> {
        let mut m = Mutation::new();
        m.purge(osis_commit::PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
        m.set(t, &workload::NOTE, &Value::Str("purged".into())).map_err(|e| sim.fail(e.to_string()))?;
        sim.commit(x, m)?.ok_or_else(|| sim.fail("wrote nothing"))?;
        Ok(())
    };
    let backdated = d.pct(50);
    if backdated {
        purge(&mut sim)?;
    }
    sim.remove(a, g, px)?;
    if !backdated {
        sim.run(5)?;
        purge(&mut sim)?;
    }
    for _ in 0..20 {
        sim.run(30)?;
        if !sim.engine(b)?.body_not_dropped(&c, &t, &k) {
            break;
        }
    }
    // Fault steps prove no liveness: seed 61000's `b` loses every dial of 600 steps to a tick past
    // the host's Hello deadline or a cut. With the faults off (`a` still cut) it must arrive.
    sim.calm = true;
    for _ in 0..40 {
        if !sim.engine(b)?.body_not_dropped(&c, &t, &k) {
            break;
        }
        sim.settle()?;
        sim.advance(61_000)?;
    }
    if sim.engine(b)?.body_not_dropped(&c, &t, &k) {
        return Err(sim.fail("the purge never reached the writer"));
    }
    sim.excused.insert(x);
    for (p, q) in cut {
        sim.heal(p, q);
    }
    sim.reconnect_all();
    if churn {
        let w = sim.cfg.weights;
        sim.cfg.weights = NetWeights { crash: 2, restart: 6, host_crash: 1, host_restart: 4, ..w };
        sim.run(60)?;
        sim.cfg.weights = NetWeights { crash: 0, host_crash: 0, ..sim.cfg.weights };
    }
    sim.run(40)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b] {
        let en = sim.engine(n)?;
        let back = en.core.ix.commits.get(&c).is_some_and(|m| m.missing.is_empty() && m.dropped.is_empty() && m.stripped.is_empty());
        let shown = en.purged_on(&t, &k).map_err(|e| sim.fail(e.to_string()))?;
        if !back || !shown.is_empty() {
            return Err(sim.fail(format!("node {n}: the body back {back}, purges shown {shown:?}")));
        }
    }
    sim.finish()
}

/// Writers online together (spec/sync.md §5, §6): an admin and three writers of one group, all
/// online, while two readers are granted at once and the admin writes items; time moves a
/// second at a time (continuous enough for the relay wait). Expected: each content body the
/// admin wrote goes up as one blob, by the admin alone; no blob is uploaded by all four
/// writers, and at most a quarter by more than one (a reader deposit is promoted by one writer,
/// rarely by one more whose view lagged); then the quiescent invariants.
pub fn concurrent_writers(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc0);
    let mut sim = NetSim::new("concurrent_writers", seed, super::NetConfig::default());
    let s = sim.add_host()?;
    let ns: Vec<usize> = (0..6).map(|_| sim.add_node(&[s], clock(&mut d))).collect::<Res<_>>()?;
    let [a, w1, w2, w3, r1, r2] = ns[..] else { return Err(sim.fail("nodes")) };
    let [pa, p1, p2, p3, q1, q2] = persons(&mut sim, [a, w1, w2, w3, r1, r2], [s; 6])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(p1, Role::Write), (p2, Role::Write), (p3, Role::Write)])?;
    sim.quiet(40)?;
    sim.count_uploads = true;
    sim.grant(a, g, q1, Role::Read)?;
    sim.grant(a, g, q2, Role::Read)?;
    let mut items = Vec::new();
    for _ in 0..4 {
        items.push(sim.item(a, g)?);
    }
    for _ in 0..90 {
        sim.settle()?;
        sim.advance(1_000)?;
    }
    sim.settle()?;
    sim.count_uploads = false;
    sim.observe()?;
    let mut by_blob: std::collections::BTreeMap<(osis_base::LabelId, osis_base::BlobId), BTreeSet<usize>> = Default::default();
    for (n, l, b) in std::mem::take(&mut sim.uploads) {
        by_blob.entry((l, b)).or_default().insert(n);
    }
    type BodyKey = (osis_base::LabelId, CommitId, Vec<(usize, usize)>);
    let mut per_body: std::collections::BTreeMap<BodyKey, BTreeSet<osis_base::BlobId>> = Default::default();
    // the wait is a spread, not an election: a writer whose view of a promotion lags (its
    // session reopened for a new step) may send too; rare. Every writer's point may fall in
    // one of the sim's 1 s steps (about 1 in 10^4 runs for some blob): never for two blobs
    let twice = by_blob.values().filter(|w| w.len() > 1).count();
    let all = by_blob.values().filter(|w| w.len() > 3).count();
    for ((l, b), who) in &by_blob {
        if who.len() > 3 && all > 1 || twice * 4 > by_blob.len().max(4) {
            let what = sim.known.get(&(*l, *b)).cloned();
            let author = match &what {
                Some((c, _)) => sim.engine(a)?.header(c).map(|h| (h.author, h.kind, h.aspects.iter().map(|x| x.ak.as_str().to_string()).collect::<Vec<_>>())),
                None => None,
            };
            return Err(sim.fail(format!("blob {b:?} under {l:?} uploaded by nodes {who:?} ({twice} of {} blobs by two nodes): {what:?} {author:?}", by_blob.len())));
        }
        if let Some((c, parts)) = sim.known.get(&(*l, *b)).cloned() {
            per_body.entry((*l, c, parts)).or_default().insert(*b);
        }
    }
    let at = sim.tid(a)?;
    for ((l, c, _), blobs) in per_body {
        let h = sim.engine(a)?.header(&c);
        let Some(h) = h.filter(|h| h.kind == osis_commit::Kind::Content && h.author == at && h.aspects.iter().any(|x| items.contains(&x.tid))) else { continue };
        let up: BTreeSet<usize> = blobs.iter().filter_map(|b| by_blob.get(&(l, *b))).flatten().copied().collect();
        if blobs.len() > 1 || up != BTreeSet::from([a]) {
            return Err(sim.fail(format!("commit {c:?} ({} aspects) went up as {} blobs by nodes {up:?}", h.aspects.len(), blobs.len())));
        }
    }
    for (n, p) in [(r1, q1), (r2, q2)] {
        if sim.engine(n)?.role_on(&g) != Some(Role::Read) {
            return Err(sim.fail(format!("node {n} ({p}) is no reader")));
        }
    }
    sim.run_until_quiescent(40)?;
    sim.finish()
}

/// Honest flows across labels, no faults (`work_sets::honest_flows_wait_for_no_resync`): each step
/// settles with time standing still, then a few resyncs pass. A label a step concerns and that
/// was left out of its marks shows as an upload at the next resync: a device paired, writes by
/// each, grants, a thing's first label, removals of a person and of a device, a role lowered, a
/// holder group and its reader removed, an invite made, redeemed and revoked.
pub fn honest_flows(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7a);
    let mut sim = NetSim::new("honest_flows", seed, NetConfig { faults: Default::default(), weights: NetWeights::default(), ..NetConfig::default() });
    let s = sim.add_host()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let e = sim.add_node(&[s], clock(&mut d))?;
    let a2 = sim.add_node(&[s], clock(&mut d))?;
    let b2 = sim.add_node(&[s], clock(&mut d))?;
    let z = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc, pe, pz] = persons(&mut sim, [a, b, c, e, z], [s, s, s, s, s])?;
    let g1 = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Read)])?;
    let g2 = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pc, Role::Read)])?;
    let h = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Read), (pc, Role::Read)])?;
    let g3 = sim.group_with(a, pa, &[s], true)?;
    sim.item(a, g3)?;
    let gb = shared_group(&mut sim, b, pb, &[s], &[(pa, Role::Read)])?;
    let gb2 = shared_group(&mut sim, b, pb, &[s], &[(pc, Role::Write)])?;
    let mut others = Vec::new();
    for _ in 0..4 {
        let o = shared_group(&mut sim, a, pa, &[s], &[(pe, Role::Read)])?;
        sim.item(a, o)?;
        others.push(o);
    }
    let t1 = sim.item(a, g1)?;
    let t2 = sim.item(a, g2)?;
    sim.item(b, gb)?;
    sim.item(b, gb2)?;
    sim.quiet(40)?;
    macro_rules! op {
        ($name:expr, $body:expr) => {{
            sim.note(format!("step: {}", $name));
            $body;
            sim.settle()?;
            for _ in 0..4 {
                sim.advance(61_000)?;
                sim.settle()?;
            }
        }};
    }
    op!("device paired a2", sim.pair(a, a2, pa)?);
    op!("device paired b2", sim.pair(b, b2, pb)?);
    op!("write by b2 acting for pb", { let mut m = Mutation::new(); m.act_as(pb); m.set(t2, &workload::REG, &Value::Str("x".into())).map_err(|e| sim.fail(e.to_string()))?; sim.commit(b2, m)?; });
    op!("write by b", { let mut m = Mutation::new(); m.set(t2, &workload::REG, &Value::Str("y".into())).map_err(|e| sim.fail(e.to_string()))?; sim.commit(b, m)?; });
    op!("write by a2", add_tag(&mut sim, a2, t1, "x")?);
    op!("grant g1 to c", sim.grant(a, g1, pc, Role::Read)?);
    op!("grant g2 to e", sim.grant(a, g2, pe, Role::Write)?);
    op!("write by e under g2", { let mut m = Mutation::new(); m.set(t2, &workload::REG, &Value::Str("e".into())).map_err(|e| sim.fail(e.to_string()))?; sim.commit(e, m)?; });
    op!("grant g3 to group h", sim.grant(a, g3, h, Role::Read)?);
    let u = sim.thing_with_secrets(a, pa)?;
    op!("grant unlabeled u to h", sim.grant(a, u, h, Role::Read)?);
    op!("first label of u", { let addrs = sim.addresses(&[s]); let r = sim.sync(a)?.create_label(&u, addrs); let (_, acts) = r.map_err(|e| sim.fail(e.to_string()))?; sim.after_node(a, acts)?; });
    op!("remove pb from g1", sim.remove(a, g1, pb)?);
    op!("write by a after", add_tag(&mut sim, a, t1, "after")?);
    op!("lower pb on g2 to read", demote(&mut sim, a, g2, pb, Some(Role::Read), PreSync::Synced)?);
    let bt2 = sim.tid(b2)?;
    op!("remove device b2 from pb", demote(&mut sim, b, pb, bt2, None, PreSync::Synced)?);
    op!("remove pc from h", sim.remove(a, h, pc)?);
    op!("remove h from g3", sim.remove(a, g3, h)?);
    let at2 = sim.tid(a2)?;
    op!("remove device a2 from pa", demote(&mut sim, a, pa, at2, None, PreSync::Synced)?);
    // an invite
    let target = others.first().copied().ok_or_else(|| sim.fail("no group"))?;
    let spec = LinkSpec { target, role: Role::Read, until: None, hosts: sim.addresses(&[s]), peers: Vec::new(), single_use: false };
    let r = sim.engine(a)?.create_link(&pa, &spec);
    let (link, _, done) = r.map_err(|e| sim.fail(format!("create_link: {e}")))?;
    op!("create link", sim.carry(a, done)?);
    let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
    op!("follow link", { let held = sim.engine(z)?.hold_key_actor(link.seed.clone()).map_err(|e| sim.fail(e.to_string()))?; let acts = sim.sync(z)?.follow(held, link.k, link.k_label, link.hosts.clone()); sim.actions(z, acts)?; });
    let r = sim.engine(z)?.redeem(&link, &pz, false);
    let done = r.map_err(|e| sim.fail(format!("redeem: {e}")))?;
    op!("redeem", { sim.engine(z)?.drop_key_actor(&l); sim.carry(z, done)?; });
    let r = sim.engine(a)?.finalize_link(&link.k, &l);
    let done = r.map_err(|e| sim.fail(format!("finalize: {e}")))?;
    op!("revoke link", sim.carry(a, done)?);
    sim.excused.extend([a2, b2]);
    sim.quiet(40)?;
    sim.finish()
}
