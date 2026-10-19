//! Phase C scenario library (plans/testing.md §5; notes/permissions.md, notes/chat.md): the
//! named membership and retention stories over sync engines and blind servers. Each sets up with
//! flows, runs a faulty schedule around the story's critical moment, checks the story's expected
//! outcome, and ends with the quiescent invariants (`check`).

use super::scenarios::{DAY_MS, clock, newest_read, persons, shared_group, sim};
use super::{NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use crate::workload;
use osis_core::{CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::Mutation;
use osis_node::flows::{Demotion, LinkSpec, PreSync};
use osis_node::sync::Event;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const HOUR_MS: u64 = 3_600_000;

/// The story marks node `n` reads on `t` (`/s/story`).
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

fn demote(sim: &mut NetSim, n: usize, target: Tid, member: Tid, new: Option<Role>, presync: PreSync) -> Res<()> {
    let new = new.map(|role| ct::Edge { role, until: None, invite: None, since: None });
    let r = sim.engine(n)?.demote(&target, &Demotion { member, new, presync });
    let done = r.map_err(|e| sim.fail(format!("node {n} demote: {e}")))?;
    sim.carry(n, done)
}

/// The revocation reference scenario (notes/permissions.md, Revocation; spec/permissions.md
/// §5.1, §5.2): Alice shares a doc with Bob; Bob goes offline and writes X; Alice removes Bob
/// without having seen X; Bob writes Y and comes back. X and Y are invalid everywhere. A re-grant
/// makes both valid again.
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
    let s = sim.add_server()?;
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
    // a re-grant validates the gap (§5.2)
    sim.grant(a, g, pb, Role::Write)?;
    sim.excused.remove(&b);
    sim.run(40)?;
    sim.run_until_quiescent(60)?;
    expect_tags(&mut sim, &[a, b, c], t, &["mon", "x", "y"], &["mon", "x", "y"])?;
    sim.finish()
}

/// A stolen device backdates (notes/permissions.md, Revocation; spec/permissions.md §5.1, §5.3):
/// the thief winds its clock back and writes; the honest device removes it with a revoke
/// backdated to the theft, so the forged edit is dropped everywhere and the device's honest edits
/// before the theft stay.
pub fn stolen_device(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x57);
    let mut sim = sim("stolen_device", seed, NetWeights::default());
    let s = sim.add_server()?;
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
/// server before the demotion; the admin syncs first, so its frontier covers them and they stay.
pub fn demotion_synced(seed: u64) -> Res<Report> {
    demotion("demotion_synced", seed, true)
}

/// Demotion without the pre-sync (spec/permissions.md §5.3): the writer's last edit has not
/// reached the admin, which stamps anyway (`Unsynced { proceed }`): that edit is lost everywhere,
/// the earlier ones stay; the demoted member still reads.
pub fn demotion_unsynced(seed: u64) -> Res<Report> {
    demotion("demotion_unsynced", seed, false)
}

fn demotion(name: &str, seed: u64, synced: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xde);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_server()?;
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
        // the admin cannot reach the server; the late edit sits there
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
        return Err(sim.fail("the demoted member does not read"));
    }
    sim.finish()
}

/// A person on node `n` follows a link's label and redeems it (spec/permissions.md §9), as the
/// osis crate does: hold L, follow K's label, wait, redeem, drop L. Err when the redemption is
/// refused (a used single-use link).
fn redeem(sim: &mut NetSim, n: usize, link: &osis_label::ShareLink, person: Tid) -> Res<Result<(), String>> {
    let l = sim.engine(n)?.hold_key_actor(link.seed.clone()).map_err(|e| sim.fail(e.to_string()))?;
    let acts = sim.sync(n)?.follow(link.k, link.k_label, link.servers.clone());
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

/// Link redemption race and single use (spec/permissions.md §9, §5.1): two strangers redeem one
/// single-use link concurrently; the sharer and the winner agree on exactly one joiner (the
/// first by the timeline's order; the loser, rotated out of K, may not learn it); the sharer
/// finalizes; a third redeemer is refused.
pub fn link_race(seed: u64) -> Res<Report> {
    links("link_race", seed, true)
}

/// Concurrent redemptions of a multi-use link (spec/permissions.md §9): both strangers join and
/// read the target; the sharer then revokes the link (removes L); a later redeemer is refused.
pub fn link_redeem(seed: u64) -> Res<Report> {
    links("link_redeem", seed, false)
}

fn links(name: &str, seed: u64, single_use: bool) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x11);
    let mut sim = sim(name, seed, NetWeights::default());
    // seed 7: a promoting upload lost on a cut connection is never retried
    sim.waivers.insert(super::WAIVE_PROMOTION);
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let x = sim.add_node(&[s], clock(&mut d))?;
    let y = sim.add_node(&[s], clock(&mut d))?;
    let z = sim.add_node(&[s], clock(&mut d))?;
    let [pa, px, py, pz] = persons(&mut sim, [a, x, y, z], [s, s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[])?;
    sim.item(a, g)?;
    sim.quiet(40)?;
    let spec = LinkSpec { target: g, role: Role::Read, until: None, servers: sim.addresses(&[s]), peers: Vec::new(), single_use };
    let r = sim.engine(a)?.create_link(&pa, &spec);
    let (link, _, done) = r.map_err(|e| sim.fail(format!("create_link: {e}")))?;
    sim.carry(a, done)?;
    sim.quiet(40)?;
    let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
    // both follow K's label, then redeem before either sees the other
    for n in [x, y] {
        sim.engine(n)?.hold_key_actor(link.seed.clone()).map_err(|e| sim.fail(e.to_string()))?;
        let acts = sim.sync(n)?.follow(link.k, link.k_label, link.servers.clone());
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

/// Move with import (spec/permissions.md §7): a shared doc moves to a team the sharer owns and
/// the writer does not read; the copy carries its history and a label of its own, its writer is
/// re-granted on it, the old thing points at it; writes continue on the copy under a lossy
/// network.
pub fn move_import(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x30);
    let mut sim = sim("move_import", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb] = persons(&mut sim, [a, b], [s, s])?;
    // the team has secrets of its own (a copy owned by an actor without them stays unwritable for
    // a member that does not read that actor, issues/flows-move-derived-owner.md)
    let team = sim.group_with(a, pa, &[s], true)?;
    let doc = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write)])?;
    let t = sim.item(a, doc)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    add_tag(&mut sim, b, doc, "before")?;
    sim.run(60)?;
    sim.quiet(40)?;
    let r = sim.engine(a)?.move_to(&doc, &team);
    let (copy, done) = r.map_err(|e| sim.fail(format!("move_to: {e}")))?;
    sim.carry(a, done)?;
    if sim.engine(a)?.move_to(&doc, &team).is_ok() {
        return Err(sim.fail("a second move of the same thing was allowed (spec/permissions.md §7)"));
    }
    // the copy is listed in the team
    let mut grp = sim.engine(a)?.get_typed(&team, &ct::GROUP).map_err(|e| sim.fail(e.to_string()))?.unwrap_or_default();
    grp.items.insert(copy);
    let mut m = Mutation::new();
    m.set(team, &ct::GROUP, &grp).map_err(|e| sim.fail(e.to_string()))?;
    sim.commit(a, m)?;
    if let Some(x) = sim.groups.iter_mut().find(|x| x.g == team) {
        x.items.push(copy);
    }
    sim.run(40)?;
    sim.quiet(60)?;
    if sim.engine(b)?.role_on(&copy).is_none_or(|r| r < Role::Write) {
        return Err(sim.fail("the writer was not re-granted on the copy"));
    }
    add_tag(&mut sim, b, copy, "after")?;
    sim.run(60)?;
    sim.run_until_quiescent(60)?;
    expect_tags(&mut sim, &[a, b], copy, &["before", "after"], &["before", "after"])?;
    for n in [a, b] {
        let moved = sim.engine(n)?.get_typed(&doc, &ct::MOVED).map_err(|e| sim.fail(e.to_string()))?;
        if moved != Some(copy) {
            return Err(sim.fail(format!("node {n}: /moved of the old thing is {moved:?}")));
        }
    }
    let _ = t;
    sim.finish()
}

/// Group chat join and leave (notes/chat.md): chat actor C with its own label, participants
/// writers of C; each joins with a persona P owned by its person (secrets of its own), C made a
/// reader of P, P listed in C's items and subgroups; messages are things owned by P in P's `/group`. A
/// participant is removed: C rotates; it holds no later epoch, the others keep posting and
/// converge.
pub fn chat_join_leave(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc4);
    let mut sim = sim("chat_join_leave", seed, NetWeights::default());
    let s = sim.add_server()?;
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

/// A persona of person `p` on node `n` for chat `chat` (notes/chat.md).
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
    // an item too: the persona's own writes (`/created`, `/group`, secrets) are in C's closure
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

/// A chat message: a thing owned by the persona, placed in its `/group`.
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
    let s = sim.add_server()?;
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

/// Label replacement (spec/sync.md §2): the admin replaces a group's label; members follow the
/// new label and converge. (Old-label cleanup is checked by `label_replacement_offline`.)
pub fn label_replacement(seed: u64) -> Res<Report> {
    replacement("label_replacement", seed, false)
}

/// Label replacement with a member offline (spec/sync.md §2: the replacement `/label` commit
/// stays under the old label, whose content entries the admin deletes, so a node that knows only
/// the old label finds the new one). Fails: issues/node-sync-gaps.md (replaced labels: the old
/// label's content entries are never deleted; the offline member does find the new label).
pub fn label_replacement_offline(seed: u64) -> Res<Report> {
    replacement("label_replacement_offline", seed, true)
}

fn replacement(name: &str, seed: u64, offline: bool) -> Res<Report> {
    use osis_proto::LabelStore;
    let mut d = Dice::new(seed ^ 0x1a);
    let mut sim = sim(name, seed, NetWeights::default());
    let s = sim.add_server()?;
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
        return Err(sim.fail(format!("the member does not follow the replacement label: {bl:?}")));
    }
    if offline {
        // the old label keeps membership-class commits and certificates (chain certificates,
        // node cards, heartbeats: they verify what stays, spec/permissions.md §4) only
        let live = sim.hub(s).map(|h| h.store().live_ids(&old).unwrap_or_default()).unwrap_or_default();
        let kept = |ak: &str| ct::is_membership_class(ak) || matches!(ak, "/created" | "/node" | "/reach" | "/seen" | "/keys");
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

/// Bundles by hand (spec/sync.md §8): a member cut off from every server gets the group's label
/// as a bundle exported by the admin and reads what the admin reads; later online, it converges.
pub fn bundles(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xbd);
    let mut sim = sim("bundles", seed, NetWeights::default());
    let s = sim.add_server()?;
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

/// Expiry races and disappearing messages (spec/commits.md §5; notes/chat.md): members post
/// messages (a thing with an expiring note, its placement expiring too) under a lossy network
/// with crashes while time passes; after the expiry no honest node reads an expired note and no
/// server holds a blob of one.
pub fn disappearing(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xd5);
    let mut sim = sim("disappearing", seed, NetWeights { crash: 1, restart: 2, ..NetWeights::default() });
    let s = sim.add_server()?;
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
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, g);
        m.set(t, &workload::NOTE, &Value::Str(format!("m{k}"))).map_err(|e| sim.fail(e.to_string()))?;
        m.expires(t, &workload::NOTE, WallMs(at)).map_err(|e| sim.fail(e.to_string()))?;
        // a crash mid-write loses the message, which is fine
        if let Some(c) = sim.commit(n, m)? {
            notes.push((t, c));
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

/// No up server holds a live entry, and no honest node a blob, of the `ak` bodies of `commits`.
fn expired_absent(sim: &mut NetSim, commits: &[CommitId], ak: &osis_core::Ak) -> Res<()> {
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
        for s in 0..sim.servers.len() {
            if sim.hub(s).is_some_and(|x| x.store().live_ids(&l).unwrap_or_default().contains(&b)) {
                return Err(sim.fail(format!("server {s} still holds the expired body {b:?} of {c:?}")));
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

/// Keep-at-most races (spec/commits.md §5): two writers overwrite an aspect kept at most 10
/// minutes after replaced, under a lossy network; an hour later every replaced body is gone from
/// the server and from honest nodes, the current value stays.
pub fn keep_at_most(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x4a);
    let mut sim = sim("keep_at_most", seed, NetWeights::default());
    let s = sim.add_server()?;
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
        m.set(t, &workload::SHORT, &Value::Str(format!("v{k}"))).map_err(|e| sim.fail(e.to_string()))?;
        written.push(sim.commit(n, m)?.ok_or_else(|| sim.fail("wrote nothing"))?);
        sim.run(20)?;
    }
    sim.run(30)?;
    sim.quiet(40)?;
    sim.advance(HOUR_MS)?;
    sim.run(20)?;
    sim.run_until_quiescent(40)?;
    let k = super::scenarios::ak(&sim, &workload::SHORT)?;
    let v = sim.engine(a)?.get(&t, &k).map_err(|e| sim.fail(e.to_string()))?;
    if v.is_none() {
        return Err(sim.fail("the current value of a keep-at-most aspect is gone"));
    }
    // the replaced bodies: every written commit but the winner; the bodies each node holds
    let mut winners = BTreeSet::new();
    let mut held = Vec::new();
    for n in [a, b] {
        let e = sim.engine(n)?;
        let h: Vec<usize> = (0..written.len()).filter(|i| written.get(*i).is_some_and(|c| e.holds_body(c, &t, &k))).collect();
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
