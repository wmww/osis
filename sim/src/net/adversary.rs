//! Phase C adversaries (plans/testing.md §5): a dishonest server, a removed member replaying
//! what it kept, a member uploading malformed blobs, a flooding depositor. Each states its
//! expected outcome; the invariant throughout is that honest nodes converge (through an honest
//! server where one is dishonest) and never read an unauthorised write.
//! Out of scope here: a stolen pairing offer (notes/api.md, Devices: offers, requests and replies
//! are app texts authenticated by the offer's secret, carried by the app and never seen by sync
//! engines or servers; within its lifetime a stolen offer pairs the thief's device, which is the
//! bound; osis crate tests own it).

use super::library::{add_tag, tags};
use super::rogue::LabelKeys;
use super::scenarios::{clock, persons, purge, shared_group, sim, write_gone};
use super::{Evil, NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use osis_core::{BlobId, CommitId, Role, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// Per honest node: the commits it had authored when it first held the removal.
type Knew = BTreeMap<Tid, BTreeSet<CommitId>>;
use osis_crypto::SeededRng;
use osis_proto::{ClientEvent, Code, Command, Entry, LabelStore, OpenKey};

/// A blob framing `plaintext` with a fresh salt and no commitments: (ID, bytes, key).
pub fn seal(sim: &mut NetSim, plaintext: &[u8]) -> Res<(BlobId, Vec<u8>, osis_crypto::Secret32)> {
    let mut rng = SeededRng::from_u64(sim.dice.u64());
    let prefix = osis_label::Prefix::new(osis_label::Prefix::random_salt(&mut rng), None, Vec::new()).map_err(|e| sim.fail(e.to_string()))?;
    let (key, blob) = osis_label::frame(&prefix, plaintext, &mut rng).map_err(|e| sim.fail(e.to_string()))?;
    Ok((osis_label::blob_id(&blob), blob, key))
}

/// A stamped entry of `blob` under `k`'s read secret and write key (wrong keys when not held).
pub fn stamped(sim: &NetSim, k: &LabelKeys, id: &BlobId, blob: Vec<u8>, key: &osis_crypto::Secret32) -> Res<Entry> {
    let read = k.read.clone().ok_or_else(|| sim.fail("no read secret held"))?;
    let wrap = osis_crypto::wrap(&read, id, key).map_err(|e| sim.fail(e.to_string()))?;
    let write = k.keys.write.clone().ok_or_else(|| sim.fail("no write key held"))?;
    let stamp = osis_label::sign_stamp(&write, &k.label, id, &wrap);
    Ok(Entry { blob, wrap, stamp })
}

/// Codes of the entry statuses and budgets among `evs`.
pub fn codes(evs: &[ClientEvent]) -> Vec<Code> {
    let mut v = Vec::new();
    for e in evs {
        match e {
            ClientEvent::EntryStatus { codes, .. } | ClientEvent::DeleteStatus { codes, .. } => v.extend(codes.iter().copied()),
            ClientEvent::Budget { code, .. } => v.push(*code),
            ClientEvent::Refused { code, .. } => v.push(*code),
            _ => {}
        }
    }
    v
}

/// A dishonest server (spec/sync.md §6; spec/requirements.md, Out of scope: servers are trusted
/// for availability only): of two servers holding every label, one holds back (reorders within a
/// stream) and replays its messages. Expected: honest nodes converge through the honest one (the
/// label invariants judge only it) and survive the protocol violations.
pub fn evil_server(seed: u64) -> Res<Report> {
    evil("evil_server", seed, Evil { drop_pct: 0, hold_pct: 10, replay_pct: 5 })
}

/// `evil_server` also silently dropping messages on open streams. Expected: a request whose
/// reply never comes times out, the node redials, everything converges and goes idle.
pub fn evil_server_drops(seed: u64) -> Res<Report> {
    evil("evil_server_drops", seed, Evil { drop_pct: 10, hold_pct: 10, replay_pct: 5 })
}

fn evil(name: &str, seed: u64, e: Evil) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xe7);
    let mut sim = sim(name, seed, NetWeights::default());
    let s0 = sim.add_server()?;
    let s1 = sim.add_server()?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let b = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s0, s1], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s0, s0, s0])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Read)])?;
    sim.item(a, g)?;
    sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    if let Some(x) = sim.servers.get_mut(s1) {
        x.evil = Some(e);
    }
    sim.dishonest.insert(s1);
    sim.run(200)?;
    sim.run_until_quiescent(60)?;
    if sim.report.evil == 0 {
        return Err(sim.fail("the evil server never misbehaved"));
    }
    sim.finish()
}

/// A removed member replays what it kept (spec/sync.md §2, §5; spec/permissions.md §5): it keeps
/// the label's old keys, entries and step. After its removal (and a purge it saw) it opens with
/// its old sync key, registers its old step, re-uploads the old entries, the purged one included,
/// and deposits a commit it wrote offline after the removal. Expected: the stale step and the
/// purged blob are refused, no honest node reads the post-removal write, honest nodes converge;
/// colluding with the server, M's secrets open no body made after its removal.
pub fn removed_replayer(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x4e);
    let mut sim = sim("removed_replayer", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let m = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pm] = persons(&mut sim, [a, b, m], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pm, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    let gone = write_gone(&mut sim, a, t, "secret")?;
    add_tag(&mut sim, m, t, "m-before")?;
    sim.run(40)?;
    sim.quiet(40)?;
    // what M keeps: the keys at the current head, every live entry
    let old = sim.label_keys(m, s, &g)?;
    let kept: Vec<Entry> = {
        let hub = sim.hub(s).ok_or_else(|| sim.fail("server down"))?;
        let st = hub.store();
        let mut v = Vec::new();
        for id in st.live_ids(&old.label).unwrap_or_default() {
            let (Some(e), Some(blob)) = (st.entry(&old.label, &id).ok().flatten(), st.blob(&id).ok().flatten()) else { continue };
            if let Some(stamp) = e.stamp {
                v.push(Entry { blob, wrap: e.wrap, stamp });
            }
        }
        v
    };
    // a purge M saw, then its removal while it is offline; it writes on
    purge(&mut sim, a, gone, t)?;
    sim.quiet(40)?;
    sim.sever(Party::N(m), Party::S(s));
    sim.remove(a, g, pm)?;
    sim.excused.insert(m);
    let mut knew = BTreeMap::new();
    run_noting(&mut sim, 40, [a, b], g, pm, &mut knew)?;
    sim.quiet(40)?;
    note_removal(&mut sim, [a, b], g, pm, &mut knew)?;
    sim.advance(60_000)?;
    note_removal(&mut sim, [a, b], g, pm, &mut knew)?;
    let evil_c = add_tag(&mut sim, m, t, "m-after")?;
    // the replay, by hand
    let mut r = sim.rogue(s)?;
    let k = old.keys.sync.clone().ok_or_else(|| sim.fail("M held no sync key"))?;
    let opened = sim.rogue_do(&mut r, Command::Open { label: old.label, key: OpenKey::Sync(k) })?;
    let stale = sim.rogue_do(&mut r, Command::Register { label: old.label, step: old.head.clone(), claim_set: None })?;
    if stale.iter().any(|e| matches!(e, ClientEvent::Registered { .. })) {
        return Err(sim.fail(format!("the server accepted a stale step from the removed member: {stale:?}; open {opened:?}")));
    }
    let replay = sim.rogue_do(&mut r, Command::Upload { label: old.label, entries: kept.clone() })?;
    let purged_ids: Vec<BlobId> = sim.known.iter().filter(|(_, (c, _))| *c == gone).map(|(k, _)| k.1).collect();
    let hub = sim.hub(s).ok_or_else(|| sim.fail("server down"))?;
    for id in &purged_ids {
        if hub.store().live_ids(&old.label).unwrap_or_default().contains(id) {
            return Err(sim.fail(format!("the replay brought back the purged blob {id:?}: {:?}", codes(&replay))));
        }
    }
    // the post-removal commit, deposited under the old wrap secret and deposit key
    let bodies = sim.engine(m)?.bodies(&evil_c).map_err(|e| sim.fail(e.to_string()))?;
    for body in bodies {
        let mut rng = SeededRng::from_u64(sim.dice.u64());
        let sealed = osis_node::labeling::seal_body(&body, &mut rng).map_err(|e| sim.fail(e.to_string()))?;
        let (id, blob, key) = (sealed.id, sealed.blob, sealed.key);
        let Some(read) = old.read.clone() else { break };
        let wrap = osis_crypto::wrap(&read, &id, &key).map_err(|e| sim.fail(e.to_string()))?;
        if let Some(dk) = &old.deposit {
            let sig = osis_label::sign_deposit(dk, &old.label, &id, &wrap);
            sim.rogue_do(&mut r, Command::Deposit { label: old.label, blob: blob.clone(), wrap, sig })?;
        }
        if let Ok(e) = stamped(&sim, &old, &id, blob, &key) {
            sim.rogue_do(&mut r, Command::Upload { label: old.label, entries: vec![e] })?;
        }
    }
    sim.rogue_close(&mut r);
    sim.unsever(Party::N(m), Party::S(s));
    run_noting(&mut sim, 60, [a, b], g, pm, &mut knew)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b] {
        let ts = tags(&mut sim, n, t)?;
        if ts.contains("m-after") || !ts.contains("m-before") {
            return Err(sim.fail(format!("node {n} reads {ts:?}: the removed member's write after removal is read, or its earlier one lost")));
        }
    }
    // colluding with the server (spec/requirements.md, Out of scope): every secret M holds opens
    // no body of a commit made after its removal
    let secrets: Vec<osis_crypto::Secret32> = sim.engine(m)?.epochs(&g).map(|e| e.read.held().map(|x| x.1.clone()).collect()).unwrap_or_default();
    let mt = sim.tid(m)?;
    let me = sim.engine(m)?.epochs(&g).map(|e| e.read.held().map(|x| format!("{:?}", x.0).chars().take(14).collect::<String>()).collect::<Vec<_>>());
    let ae = sim.engine(a)?.epochs(&g).map(|e| e.read.held().map(|x| format!("{:?}", x.0).chars().take(14).collect::<String>()).collect::<Vec<_>>());
    let (ta, tb) = (sim.tid(a)?, sim.tid(b)?);
    let hub = sim.hub(s).ok_or_else(|| sim.fail("server down"))?;
    let mut checked = 0;
    for id in hub.store().live_ids(&old.label).unwrap_or_default() {
        let Some((c, _)) = sim.known.get(&(old.label, id)) else { continue };
        // honest commits written after their author had applied the removal (spec/requirements.md,
        // Out of scope: revocation reaches a writer when it next syncs; M's own are M's)
        let late = sim.nodes.get(a).and_then(|x| x.sync.as_ref()).and_then(|x| x.engine().header(c)).is_some_and(|h| h.author != mt && knew.get(&h.author).is_some_and(|own| !own.contains(c)));
        let Some(e) = hub.store().entry(&old.label, &id).ok().flatten() else { continue };
        if late {
            checked += 1;
            if osis_label::unwrap_any(secrets.iter(), &id, &e.wrap).is_some() {
                let h = sim.nodes.get(a).and_then(|x| x.sync.as_ref()).and_then(|x| x.engine().header(c)).map(|h| format!("author {} kind {:?} ts {} (written after its author held the removal) aspects {:?}", h.author, h.kind, h.ts.wall_ms().0, h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>()));
                return Err(sim.fail(format!("the removed member's secrets open {id:?} of {c:?}, made after its removal: {h:?}; M epochs {me:?} A epochs {ae:?} a {ta} b {tb} m {mt}")));
            }
        }
    }
    if checked == 0 {
        return Err(sim.fail("no body made after the removal to check"));
    }
    sim.finish()
}

/// Notes, per node tid, the commits it had authored when it is first seen holding `member`'s
/// removal from `g` (noted after the step that brought it, so judged leniently, never wrongly
/// late).
fn note_removal(sim: &mut NetSim, nodes: [usize; 2], g: Tid, member: Tid, knew: &mut Knew) -> Res<()> {
    for n in nodes {
        let t = sim.tid(n)?;
        if knew.contains_key(&t) {
            continue;
        }
        let Some(e) = sim.nodes.get_mut(n).and_then(|x| x.sync.as_mut()).map(|x| x.engine_mut()) else { continue };
        let members = e.get_typed(&g, &osis_schema::core_types::MEMBERS).ok().flatten().unwrap_or_default();
        if !members.contains_key(&member) {
            let own: BTreeSet<CommitId> = e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.author == t)).collect();
            knew.insert(t, own);
        }
    }
    Ok(())
}

/// `sim.run(n)` noting after each step who holds the removal.
fn run_noting(sim: &mut NetSim, n: u64, nodes: [usize; 2], g: Tid, member: Tid, knew: &mut Knew) -> Res<()> {
    note_removal(sim, nodes, g, member, knew)?;
    sim.calm = false;
    for _ in 0..n {
        sim.step()?;
        note_removal(sim, nodes, g, member, knew)?;
    }
    Ok(())
}

/// A member uploads malformed blobs (spec/sync.md §5, spec/commits.md §4; spec/versioning.md §2:
/// malformed data is rejected, never parked): garbage bytes, a well-framed blob of garbage, a
/// real commit under a prefix that disagrees with its header, a wrap for another blob. Expected:
/// the server keeps them (it cannot judge them), honest nodes reject them without failing, keep
/// syncing and converge.
pub fn malformed_blobs(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x6a);
    let mut sim = sim("malformed_blobs", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let m = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pm] = persons(&mut sim, [a, b, m], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pm, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    let c = add_tag(&mut sim, m, t, "real")?;
    sim.run(30)?;
    sim.quiet(40)?;
    let k = sim.label_keys(m, s, &g)?;
    let mut r = sim.rogue(s)?;
    let mut entries = Vec::new();
    // garbage bytes, stamped: no prefix
    let junk: Vec<u8> = (0..300).map(|_| sim.dice.u64() as u8).collect();
    let jid = osis_label::blob_id(&junk);
    let jkey = osis_crypto::Secret32::from_bytes([7; 32]);
    entries.push(stamped(&sim, &k, &jid, junk, &jkey)?);
    // a well-framed blob of garbage plaintext
    let pt: Vec<u8> = (0..200).map(|_| sim.dice.u64() as u8).collect();
    let (id, blob, key) = seal(&mut sim, &pt)?;
    entries.push(stamped(&sim, &k, &id, blob, &key)?);
    // a real commit under a prefix without its commitments (disagrees with the header)
    let bodies = sim.engine(m)?.bodies(&c).map_err(|e| sim.fail(e.to_string()))?;
    if let Some(body) = bodies.first() {
        let (id, blob, key) = seal(&mut sim, &body.plaintext)?;
        entries.push(stamped(&sim, &k, &id, blob, &key)?);
        // and the same commit wrapped with another blob's key
        let (id2, blob2, _) = seal(&mut sim, &body.plaintext)?;
        entries.push(stamped(&sim, &k, &id2, blob2, &key)?);
    }
    // a blob whose framing version the server does not know is kept (spec/wire.md §5)
    sim.rogue_do(&mut r, Command::Upload { label: k.label, entries })?;
    // a frame that is no message
    sim.rogue_raw(&mut r, osis_proto::encode_frame(&[0xff, 0x00, 0x13]))?;
    sim.rogue_close(&mut r);
    sim.run(80)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b, m] {
        if !tags(&mut sim, n, t)?.contains("real") {
            return Err(sim.fail(format!("node {n} lost the real write")));
        }
    }
    sim.finish()
}

/// A flooding depositor (spec/sync.md §5, deposit budget; notes/sync.md, server policy): a reader
/// holding the deposit key deposits hundreds of fresh encryptions of a body of the label.
/// Expected: bounded: the server accepts at most the label's deposit budget and refuses the rest;
/// honest nodes delete the duplicates, keep writing and converge.
pub fn deposit_flood(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xf1);
    let mut sim = sim("deposit_flood", seed, NetWeights::default());
    let s = sim.add_server()?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let f = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pf] = persons(&mut sim, [a, b, f], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pf, Role::Read)])?;
    let t = sim.item(a, g)?;
    sim.reconnect_all();
    sim.quiet(40)?;
    let k = sim.label_keys(f, s, &g)?;
    let dk = k.deposit.clone().ok_or_else(|| sim.fail("the reader holds no deposit key"))?;
    let read = k.read.clone().ok_or_else(|| sim.fail("the reader holds no read secret"))?;
    // fresh encryptions of a body of the label (valid duplicates: junk is malformed_blobs')
    let body = sim.engine(f)?.label_bodies(&g).map_err(|e| sim.fail(e.to_string()))?.into_iter().next().ok_or_else(|| sim.fail("no body"))?;
    let mut rng = SeededRng::from_u64(sim.dice.u64());
    let mut r = sim.rogue(s)?;
    let mut ok = 0u64;
    let mut refused = 0u64;
    let mut budget = None;
    for i in 0..400u64 {
        let sealed = osis_node::labeling::seal_body(&body, &mut rng).map_err(|e| sim.fail(e.to_string()))?;
        let (id, blob, key) = (sealed.id, sealed.blob, sealed.key);
        let wrap = osis_crypto::wrap(&read, &id, &key).map_err(|e| sim.fail(e.to_string()))?;
        let sig = osis_label::sign_deposit(&dk, &k.label, &id, &wrap);
        let evs = sim.rogue_do(&mut r, Command::Deposit { label: k.label, blob, wrap, sig })?;
        for e in &evs {
            if let ClientEvent::Budget { code: Code::OK, entries_left, .. } = e
                && budget.is_none()
            {
                budget = Some(entries_left + 1);
            }
        }
        for c in codes(&evs) {
            if c == Code::OK {
                ok += 1;
            } else {
                refused += 1;
            }
        }
        if i % 50 == 0 {
            sim.advance(1_000)?;
        }
    }
    sim.rogue_close(&mut r);
    let budget = budget.unwrap_or(0);
    if ok > budget || refused == 0 {
        return Err(sim.fail(format!("deposit flood: {ok} accepted, {refused} refused (budget {budget})")));
    }
    sim.excused.insert(f);
    add_tag(&mut sim, b, t, "still")?;
    sim.run(60)?;
    sim.run_until_quiescent(40)?;
    for n in [a, b] {
        if !tags(&mut sim, n, t)?.contains("still") {
            return Err(sim.fail(format!("node {n} does not read the honest write after the flood")));
        }
    }
    sim.finish()
}
