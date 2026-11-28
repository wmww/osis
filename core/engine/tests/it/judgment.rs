//! Judgment conformance vectors (core/test/vectors/README.md, `judgment/`): histories played by
//! the order harness (`order::play`), delivered as a peer holding the sync IDs holds them, judged
//! by a fresh node in a given arrival order; the expected verdicts are what this engine judges.
//! `judgment_vectors_<file>_*`, one test per file, replay every generated case (its inputs only)
//! through a fresh engine and compare; `judgment_vectors_can_fail` (ignored) checks a changed verdict
//! fails each case, and a shorter order some case of each file.

use crate::order::{Played, Step, play};
use osis_base::{CommitId, Role, Time};
use osis_crypto::{Secret32, SeededRng};
use osis_engine::local_peer::{LocalPeer, Package};
use osis_vectors::file::{Record as Rec, VecFile};
use std::collections::{BTreeMap, BTreeSet};

/// Fields of a case that are inputs; every other field is expected output.
const INPUTS: [&str; 7] = ["case", "spec", "source", "read-secret", "now", "entries", "order"];
/// Header fields that are not expected lines.
const HEADER: [&str; 4] = ["subject", "spec", "source", "setup"];
const GEN: &str = "osis-engine judgment generator (tests/it/judgment.rs)";

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One arrival step: receive entry i (a body it opens, else a referenced blob), advance
/// the clock by ms and run timers, drop every aspect of entry i's body as covered (node-sync's
/// compaction drop).
#[derive(Clone, Copy, Debug)]
enum Tok {
    In(usize),
    Wait(u64),
    Drop(usize),
}

fn render_order(o: &[Tok]) -> String {
    o.iter().map(|t| match t {
        Tok::In(i) => i.to_string(),
        Tok::Wait(ms) => format!("+{ms}"),
        Tok::Drop(i) => format!("d{i}"),
    }).collect::<Vec<_>>().join(",")
}

fn parse_order(s: &str) -> Vec<Tok> {
    s.split(',').map(|t| match (t.strip_prefix('+'), t.strip_prefix('d')) {
        (Some(ms), _) => Tok::Wait(ms.parse().unwrap()),
        (_, Some(i)) => Tok::Drop(i.parse().unwrap()),
        _ => Tok::In(t.parse().unwrap()),
    }).collect()
}

/// What `lay` lays out: the entry bytes (README.md, `judgment/`), each entry's commit index, the
/// entries that are referenced blobs and the length of the setup's prefix.
struct Laid {
    bytes: Vec<u8>,
    of: Vec<usize>,
    refs: BTreeSet<usize>,
    setup: usize,
}

/// A played history's entries as a peer holding its sync IDs holds them: per commit the blobs it
/// references, each under a filler wrap (left out where the case needs no bytes of them: the
/// chunks of `t:blob.0`, which nothing waits for), then its one blob (sections per sync ID, each
/// under that sync ID's read secret, spec/wire.md §4) once per sync ID with a part of it, wrapped
/// under that sync ID's read secret. Every thing is under one sync ID (read secret `0a`); with
/// `second`, every thing but G under a second one (read secret `1a`).
fn lay(played: &Played, second: bool) -> Laid {
    let mut rng = SeededRng::from_u64(0);
    let reads = read_secrets(second);
    let mut ents: Vec<([u8; osis_crypto::WRAP_LEN], Vec<u8>)> = Vec::new();
    let mut of = Vec::new();
    let mut refs = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut setup = 0;
    // the judging node's grants on the things outside G (`Played::access`), as the first entries
    // after the setup (a node is granted a thing before it fetches it), counted with the setup's
    // last commit
    let access: Vec<Package> = played.access.iter().map(|(_, pk)| pk.clone()).collect();
    let laid_packs: Vec<(usize, &Package)> = played.packs[..played.base].iter().enumerate().chain(access.iter().map(|pk| (played.base.saturating_sub(1), pk))).chain(played.packs.iter().enumerate().skip(played.base)).collect();
    for (ci, pk) in laid_packs {
        let cb = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        // bare headers name no list by link in these histories: the aspects are at hand
        let under = |ai: usize| second && cb.header.aspects[ai].tid != played.things[0] && played.things.contains(&cb.header.aspects[ai].tid);
        let readers: Vec<bool> = cb.parts.iter().map(|p| under(p.ai)).collect::<BTreeSet<_>>().into_iter().collect();
        let read_of = |second: bool| &reads[usize::from(second)];
        if !readers.is_empty() && !cb.header.aspects.iter().any(|a| a.ak.as_str() == "t:blob.0") {
            for (id, b) in &pk.blobs {
                if seen.insert(*id) {
                    ents.push((osis_crypto::filler_wrap(&mut rng), b.clone()));
                    refs.insert(of.len());
                    of.push(ci);
                }
            }
        }
        if !cb.parts.is_empty() {
            let env = osis_commit::seal_commit(&cb, &cb.header, |ai| (cb.header.aspects[ai].tid, under(ai)), |r, _| Some((read_of(r.1).clone(), vec![])), &[], &mut rng).unwrap();
            let sealed = osis_engine::sync_ids::frame_envelope(&env, &cb.header, osis_blob::Class::Durable, &mut rng, &cb).unwrap();
            for r in readers {
                ents.push((osis_crypto::wrap(read_of(r), &sealed.id, &sealed.key, 1).unwrap(), sealed.blob.clone()));
                of.push(ci);
            }
        }
        if ci < played.base && !access.iter().any(|a| a.id == pk.id) {
            setup = ents.len();
        }
    }
    let write = |n: usize| {
        let mut out = Vec::new();
        for (wrap, b) in ents.iter().take(n) {
            out.extend_from_slice(wrap);
            out.extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
            out.extend_from_slice(b);
        }
        out
    };
    Laid { bytes: write(ents.len()), of, refs, setup: write(setup).len() }
}

/// The entries of `bytes`, each with its blob's ID.
fn entries(bytes: &[u8]) -> Vec<(osis_base::BlobId, [u8; osis_crypto::WRAP_LEN], Vec<u8>)> {
    osis_vectors::subjects::judgment::entries(bytes).unwrap().into_iter().map(|(wrap, b)| (osis_blob::blob_id(&b), wrap, b)).collect()
}

fn role(r: Role) -> &'static str {
    match r {
        Role::Sync => "sync",
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
    }
}

fn hash_hex(b: &[u8]) -> String {
    osis_base::hex::encode(&osis_base::hash::hash(b))
}

/// `replay`, once per input in this process: generating a file judges each case, and replaying it
/// from its text then finds the same inputs (the text carries all of them exactly) or judges anew.
/// `setup`: the length of the file's setup, the first entries of `bytes`.
fn judged(bytes: &[u8], setup: usize, reads: &[Secret32], now: Time, order: &[Tok]) -> Vec<(String, String)> {
    type Key = (String, Vec<String>, u64, String);
    static SEEN: std::sync::Mutex<BTreeMap<Key, Vec<(String, String)>>> = std::sync::Mutex::new(BTreeMap::new());
    let key = (hash_hex(bytes), reads.iter().map(|r| osis_base::hex::encode(r.expose())).collect(), now.0, render_order(order));
    if let Some(v) = SEEN.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return v.clone();
    }
    let v = replay(bytes, setup, reads, now, order);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).insert(key, v.clone());
    v
}

/// Delivers `order` of the entries to a fresh node at `now` within one pass (its end never
/// comes, `Engine::settle_needs`): the order harness's node under test (`order::judge_at`,
/// granted read in the setup and in its first entries), holding every thing an entry writes on,
/// so what it judges is a function of the entries alone (spec/commits.md §4 Outside the node
/// closure, §5 What a held thing needs); what it judges, as the expected fields of a case
/// (README.md, `judgment/`). An order starting with the setup's entries (`setup`: their length in
/// `bytes`) as laid starts from a copy of the node that received them so, made once per
/// (`now`, setup, read secrets, held things) in this process (notes/test-harnesses.md, Copied
/// worlds).
fn replay(bytes: &[u8], setup: usize, reads: &[Secret32], now: Time, order: &[Tok]) -> Vec<(String, String)> {
    let ents = entries(bytes);
    let mut ids = BTreeSet::new();
    // a filler wrap opens under no read secret (spec/crypto.md §5)
    // an entry delivers its sync ID's section: the one sealed under the read secret its wrap
    // opened with (a node holding one sync ID's secret reads that sync ID's parts)
    // (each entry opened once)
    let opened: Vec<Option<(Vec<u8>, osis_commit::CommitBlob)>> = ents.iter().map(|(id, wrap, blob)| {
        osis_blob::unwrap_any(reads, id, wrap).map(|(ri, key)| {
            let (_, pt) = osis_blob::open(blob, &key).unwrap();
            let env = osis_commit::Envelope::decode(&pt).unwrap();
            let o = env.open(|_| vec![reads[ri].clone()]).unwrap();
            (o.commit.encode(), o.commit)
        })
    }).collect();
    let open = |i: usize| opened[i].as_ref();
    // it holds every thing an entry it opens writes on, as a node holding the sync IDs does: only
    // content of a thing in the node closure applies (spec/commits.md §4 Outside the node closure)
    let mut held = BTreeSet::new();
    for i in 0..ents.len() {
        if let Some((_, cb)) = open(i) {
            held.extend(cb.header.aspects.iter().map(|a| a.tid));
        }
    }
    // it syncs those things' sync IDs: it follows each held thing's locator once its sync ID is
    // known (a link it redeems, spec/sync-set.md §2 First entry), as a node handed them would
    let follow = |p: &mut osis_engine::local_peer::Peer| {
        for t in &held {
            if let Ok(Some(l)) = p.engine.locator(t, Vec::new()) {
                p.engine.follow_locator(&l);
            }
        }
    };
    let ingest = |p: &mut osis_engine::local_peer::Peer, i: usize| match open(i) {
        Some((pt, _)) => {
            follow(p);
            let _ = p.engine.ingest(pt, Vec::new());
            follow(p);
        }
        None => {
            p.engine.put_blobs(vec![(ents[i].0, ents[i].2.clone())]).unwrap();
            follow(p);
            p.reexamine().unwrap();
        }
    };
    let n = entries(&bytes[..setup]).len();
    let lead = if order.len() >= n && order.iter().zip(0..n).all(|(t, i)| matches!(t, Tok::In(j) if *j == i)) { n } else { 0 };
    let key = format!("judgment::received/{}/{}/{:?}/{held:?}/{lead}", now.0, hash_hex(&bytes[..setup]), reads.iter().map(|r| hash_hex(r.expose())).collect::<Vec<_>>());
    let mut p = LocalPeer::cached(&key, || {
        // a fresh node at `now`: built once per `now`
        let mut p = LocalPeer::cached(&format!("judgment::fresh/{}", now.0), || (LocalPeer::apart(vec![crate::order::judge_at(now)], 0), ())).0;
        for t in &held {
            p.peers[0].engine.hold(osis_base::Strong(*t)).unwrap();
        }
        for i in 0..lead {
            ingest(&mut p.peers[0], i);
        }
        (p, ())
    })
    .0
    .peers
    .remove(0);
    follow(&mut p);
    for (at, t) in order.iter().enumerate() {
        match *t {
            Tok::In(i) => {
                if let Some((_, cb)) = open(i) {
                    ids.insert(cb.id());
                }
                // the first `lead` the copied node received
                if at >= lead {
                    ingest(&mut p, i);
                }
            }
            Tok::Wait(ms) => {
                p.clock.advance(ms);
                p.tick().unwrap();
            }
            Tok::Drop(i) => {
                let (_, cb) = open(i).unwrap();
                for part in &cb.parts {
                    let a = &cb.header.aspects[part.ai];
                    p.engine.drop_body(&cb.id(), &a.tid, &a.ak).unwrap();
                }
            }
        }
    }
    // what counts as never received again (a body dropped while invalid, valid since; one whose
    // cover fell) is fetched where present (spec/sync-judgement.md §2): every body entry received comes again
    for t in order {
        if let Tok::In(i) = *t
            && let Some((pt, _)) = open(i)
        {
            let _ = p.engine.ingest(pt, Vec::new());
        }
    }
    p.reexamine().unwrap();
    observe(&mut p.engine, &ids)
}

/// What a node holding `ids` shows of them, as a user could see it: each held part's validity (or
/// its edge write applied in the walk), each touched thing's roster and each touched aspect's read.
pub(crate) fn observe(e: &mut osis_engine::Engine, ids: &BTreeSet<CommitId>) -> Vec<(String, String)> {
    let hex = |c: &CommitId| osis_base::hex::encode(&c.0);
    let mut held: Vec<(osis_base::Ts, CommitId)> = ids.iter().filter_map(|c| e.header(c).map(|h| (h.ts, *c))).collect();
    held.sort();
    let mut out = Vec::new();
    let mut things = BTreeSet::new();
    let mut aspects = BTreeSet::new();
    for (_, c) in &held {
        let h = e.header(c).unwrap();
        for (ai, a) in h.aspects.iter().enumerate() {
            things.insert(a.tid);
            aspects.insert((a.tid, a.ak.clone()));
            // an edge write has no content verdict: it applies in the walk or not (§5.1)
            let valid = match a.ak.as_str() {
                "roles.0" if e.edge_write_applied(&a.tid, c) => "applied",
                "roles.0" => "unapplied",
                _ if e.part_valid(c, ai).unwrap() => "valid",
                _ => "invalid",
            };
            // a piece by its place among its aspect's (spec/wire.md §4 Pieces)
            let pieces = h.aspect_parts(&a.tid, a.ak.as_str());
            let name = match pieces.len() {
                1 => format!("body {} {} {}", hex(c), a.tid, a.ak.as_str()),
                _ => format!("body {} {} {} {}", hex(c), a.tid, a.ak.as_str(), ai - pieces.start),
            };
            out.push((name, valid.to_string()));
        }
    }
    for t in &things {
        let roster: Vec<String> = e.roster(t).iter().map(|(h, ed)| {
            let mut s = format!("{h}:{}", role(ed.role));
            if let Some(u) = ed.until {
                s += &format!(":until={}", u.0);
            }
            if ed.may_grant {
                s += ":may-grant";
            }
            s
        }).collect();
        out.push((format!("thing {t}"), format!("roster={}", roster.join(","))));
    }
    for (t, a) in &aspects {
        let read = e.get(t, a).unwrap().map_or("absent".to_string(), |v| hash_hex(&osis_base::encode(&v)));
        out.push((format!("aspect {t} {}", a.as_str()), format!("read={read}")));
    }
    out
}

/// Named arrival orders from the history, each entry's commit index and the entries that are
/// referenced blobs.
type OrdersFn = fn(&Played, &[usize], &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)>;

/// A history and the arrival orders it is judged in.
struct Scenario {
    name: &'static str,
    spec: &'static str,
    source: &'static str,
    steps: Vec<Step>,
    /// Orders by entry (`OrdersFn`); `None`: as made, and the setup first with the rest reversed.
    orders: Option<OrdersFn>,
}

fn default_orders(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
    let made: Vec<Tok> = (0..of.len()).map(Tok::In).collect();
    let k = of.iter().position(|c| *c >= played.base).unwrap_or(of.len());
    let rev = (0..k).chain((k..of.len()).rev()).map(Tok::In).collect();
    vec![("as made", made), ("reversed", rev)]
}

fn read_secrets(second: bool) -> Vec<Secret32> {
    let mut r = vec![s32(0x0a)];
    if second {
        r.push(s32(0x1a));
    }
    r
}

/// `second`: every thing but G under a second sync ID (`lay`).
fn generate(spec: &str, scenarios: Vec<Scenario>, second: bool) -> VecFile {
    let mut setup: Option<Vec<u8>> = None;
    let mut cases = Vec::new();
    let reads = read_secrets(second);
    let reads_hex = reads.iter().map(|x| osis_base::hex::encode(x.expose())).collect::<Vec<_>>().join(",");
    for sc in scenarios {
        let played = play(0, &sc.steps);
        let laid = lay(&played, second);
        let n = laid.setup;
        assert_eq!(setup.get_or_insert_with(|| laid.bytes[..n].to_vec())[..], laid.bytes[..n], "{}: one setup per file", sc.name);
        let orders = sc.orders.unwrap_or(default_orders)(&played, &laid.of, &laid.refs);
        let first = format!("{}, {}", sc.name, orders[0].0);
        for (i, (oname, order)) in orders.into_iter().enumerate() {
            let name = format!("{}, {oname}", sc.name);
            let mut r = Rec::new().with("case", &name).with("spec", sc.spec).with("source", sc.source).with("read-secret", &reads_hex).with("now", played.now.0.to_string());
            r = if i == 0 { r.with("entries", osis_base::hex::encode(&laid.bytes[n..])) } else { r.with("entries", format!("as in {first}")) };
            r = r.with("order", render_order(&order));
            for (k, v) in judged(&laid.bytes, laid.setup, &reads, played.now, &order) {
                r = r.with(&k, v);
            }
            cases.push(r);
        }
    }
    // the expected lines every case shares (the setup's, mostly) go in the header once
    let expected = |r: &Rec| r.fields.iter().filter(|(k, _)| !INPUTS.contains(&k.as_str())).cloned().collect::<Vec<_>>();
    let shared: Vec<(String, String)> = expected(&cases[0]).into_iter().filter(|f| cases.iter().all(|c| c.fields.contains(f))).collect();
    for c in &mut cases {
        c.fields.retain(|f| !shared.contains(f));
    }
    let mut header = Rec::new().with("subject", "judgment").with("spec", spec).with("source", GEN).with("setup", osis_base::hex::encode(&setup.unwrap()));
    header.fields.extend(shared);
    VecFile { header, cases }
}

/// The judgment files (`judgment/<name>.vec`, never written out): their names, one test each.
const FILES: [&str; 6] = ["models", "rules", "edges", "bounds", "sync IDs", "blobs"];

/// The judgment file `judgment/<name>.vec`, generated in memory: its path and text.
fn file(name: &str) -> (String, String) {
    let (spec, scenarios, second) = match name {
        "models" => ("spec/permissions.md §5", models(), false),
        "rules" => ("spec/permissions.md §3, §5, spec/commits.md §5, spec/crdt.md §4", rules(), false),
        "edges" => ("spec/permissions.md §2, §5, §7", edges().into_iter().chain(may_grants()).collect(), false),
        "bounds" => ("spec/permissions.md §5, spec/commits.md §5, spec/crdt.md §4", remerges().into_iter().chain(bounds()).collect(), false),
        "sync IDs" => ("spec/commits.md §4, spec/sync-judgement.md §1", sync_ids(), true),
        "blobs" => ("spec/commits.md §4, spec/crdt.md §8, spec/permissions.md §5.1", blobs(), false),
        _ => unreachable!("no judgment file {name}"),
    };
    (format!("judgment/{name}.vec"), generate(spec, scenarios, second).render())
}

fn files() -> Vec<(String, String)> {
    FILES.iter().map(|n| file(n)).collect()
}

/// Pinned reference scenarios of the role rules played on the engine:
/// peer 0 is G's mint admin, 1 writes, 2 is admin (`order::play`'s setup).
fn models() -> Vec<Scenario> {
    use Step::*;
    let w = |by, v| Write { by, t: 0, op: 0, k: 0, v };
    let tick = Advance { who: None, ms: 1000 };
    // A demotes X now, with a frontier of what A received of X's writes
    let revoke = Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false };
    vec![
        Scenario {
            name: "pre-revoke edit unseen by the revoker",
            spec: "spec/permissions.md §5.2",
            source: "hand-picked: a write the revoker had not received when it demoted its writer (unseen: both invalid)",
            steps: vec![w(1, 1), tick.clone(), revoke.clone(), tick.clone(), w(1, 2)],
            orders: None,
        },
        Scenario {
            name: "pre-revoke edit seen by the revoker",
            spec: "spec/permissions.md §5.1, §5.2",
            source: "hand-picked: a write the revoker had received when it demoted its writer (seen: the first stands)",
            steps: vec![w(1, 1), Sync { from: 1, to: 0 }, tick.clone(), revoke.clone(), tick.clone(), w(1, 2)],
            orders: None,
        },
        Scenario {
            name: "revoked writer re-granted",
            spec: "spec/permissions.md §5.2",
            source: "hand-picked: a demoted writer re-granted (re-granted: both stand)",
            steps: vec![w(1, 1), Sync { from: 1, to: 0 }, tick.clone(), revoke.clone(), tick.clone(), w(1, 2), tick.clone(), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Write) }],
            orders: None,
        },
        Scenario {
            name: "snapshot before the revoke carries the unseen edit",
            spec: "spec/permissions.md §5.2",
            source: "spec/permissions.md §5.2 (a snapshot is no role event: at t=4 the delta stays invalid)",
            steps: vec![w(1, 1), Sync { from: 1, to: 2 }, tick.clone(), Compact { by: 2, t: 0, op: 0 }, tick.clone(), revoke.clone()],
            orders: None,
        },
        Scenario {
            name: "snapshot after the revoke carries the unseen edit",
            spec: "spec/permissions.md §5.2",
            source: "spec/permissions.md §5.2 (a snapshot is no role event: at t=6 likewise)",
            steps: vec![w(1, 1), Sync { from: 1, to: 2 }, tick.clone(), revoke.clone(), tick.clone(), Compact { by: 2, t: 0, op: 0 }],
            orders: None,
        },
        Scenario {
            name: "concurrent cross removals, the earlier wins",
            spec: "spec/permissions.md §5.1",
            source: "hand-picked: two admins removing each other concurrently (the earlier wins)",
            steps: vec![Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Sync { from: 0, to: 1 }, tick.clone(), Edge { by: 1, t: 0, holder: 2, role: None }, tick.clone(), Edge { by: 2, t: 0, holder: 1, role: None }],
            orders: None,
        },
        Scenario {
            name: "concurrent cross removals, the mint admin removes the earlier unseen",
            spec: "spec/permissions.md §5.1",
            source: "hand-picked: two admins removing each other concurrently (the mint admin's removal of x drops x's removal of y)",
            steps: vec![Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Sync { from: 0, to: 1 }, tick.clone(), Edge { by: 1, t: 0, holder: 2, role: None }, tick.clone(), Edge { by: 2, t: 0, holder: 1, role: None }, tick.clone(), Edge { by: 0, t: 0, holder: 1, role: None }],
            orders: None,
        },
    ]
}

/// One hand-picked scenario per rule family (core/test/vectors/README.md, `judgment/`).
fn rules() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    vec![
        Scenario {
            name: "keys.0: a writer writes the write keyset field",
            spec: "spec/permissions.md §3",
            source: "hand-built: 1 (write on G) writes only field 1 of G's keys.0: needs write, valid",
            steps: vec![HostileKeys { by: 1, t: 0, field: 1 }],
            orders: None,
        },
        Scenario {
            name: "keys.0: a writer writes the deposit seed",
            spec: "spec/permissions.md §3",
            source: "hand-built: 1 (write on G) writes field 5 of G's keys.0: needs admin, invalid",
            steps: vec![HostileKeys { by: 1, t: 0, field: 5 }],
            orders: None,
        },
        Scenario {
            name: "frontier coverage: two writes before the demotion, one received",
            spec: "spec/permissions.md §5.1, §5.2",
            source: "hand-picked: W1 by 1 reaches 0, W2 by 1 does not; 0 removes 1 with its frontier (W1 valid, W2 invalid)",
            steps: vec![Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, Sync { from: 1, to: 0 }, tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 2 }, tick.clone(), Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false }],
            orders: None,
        },
        Scenario {
            name: "re-grant: a write in the gap",
            spec: "spec/permissions.md §5.2",
            source: "hand-picked: 0 removes 1, 1 (not knowing) writes, 0 grants 1 write again (the gap write valid)",
            steps: vec![Edge { by: 0, t: 0, holder: 1, role: None }, tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, tick.clone(), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Write) }],
            orders: None,
        },
        Scenario {
            name: "cover drop and uncover",
            spec: "spec/permissions.md §5.2, spec/commits.md §5",
            source: "hand-picked: W by 1, S by 2 covers it, the node drops W as covered, 2 is demoted before S (S invalid: W counts as never received), W arrives again",
            steps: vec![Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, Sync { from: 1, to: 2 }, tick.clone(), Compact { by: 2, t: 0, op: 0 }, tick.clone(), Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false }],
            orders: Some(|played, of, _| {
                let (k, base) = (of.iter().position(|c| *c >= played.base).unwrap(), played.base);
                // the setup, W, S, W dropped as covered, the demotion; W comes again as fetched
                // (`replay`)
                let (w, s, d) = (k, k + 1, k + 2);
                assert_eq!((of[w], of[s], of[d], of.len()), (base, base + 1, base + 2, k + 3), "one body each");
                vec![("arriving again", (0..k).map(Tok::In).chain([Tok::In(w), Tok::In(s), Tok::Drop(w), Tok::In(d)]).collect())]
            }),
        },
        Scenario {
            name: "purge on replace, killer removed",
            spec: "spec/commits.md §5",
            source: "hand-picked: purge on replace; W1 by 1, W2 by 2 kills it, 2 is removed (W2 invalid): W1 is the value again in either order",
            steps: vec![Write { by: 1, t: 0, op: 18, k: 0, v: 1 }, tick.clone(), Write { by: 2, t: 0, op: 18, k: 0, v: 2 }, tick.clone(), Edge { by: 0, t: 0, holder: 2, role: None }],
            orders: None,
        },
        Scenario {
            name: "un-merge of a write nested under an invalid creation",
            spec: "spec/crdt.md §4.6, spec/permissions.md §5.2",
            source: "order harness, shrunk: C puts an entry, B (sent it alone) writes inside it and compacts, A lowers C to read (an audit with no frontier)",
            steps: vec![Nested { by: 2, other: 1, t: 6, k: 0, text: false, compact: true, also: false }, New { by: 2, admin: 1, write: true }, Send { from: 1, to: 0, back: 1 }, Edge { by: 0, t: 2, holder: 2, role: Some(Role::Read) }],
            orders: None,
        },
    ]
}

/// One hand-picked scenario per rule of `until` and may-grant (spec/permissions.md §2).
fn edges() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    vec![
        // spec/permissions.md §2, §5.2: an edge counts as removed from `until` on
        Scenario {
            name: "until passes: the edge ends",
            spec: "spec/permissions.md §2, §5.2",
            source: "hand-picked: 0 sets 1's write edge to end 2.5 s on (1 not told), 1 writes 1 s and 3 s on (the first valid, the second invalid: the edge expired)",
            steps: vec![Grant { by: 0, t: 0, holder: 1, role: Role::Write, until: Some(2500), may_grant: false, flow: false }, tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, tick.clone(), tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 2 }],
            orders: None,
        },
        // spec/permissions.md §2: a may-grant grant adds an edge up to its signer's role (beyond
        // it: `may_grants()`)
        Scenario {
            name: "may-grant grant",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-picked: 0 removes 2 and grants 1 write with may-grant; 1 grants 2 write by may-grant (applies); 2 writes (valid)",
            steps: vec![Edge { by: 0, t: 0, holder: 2, role: None }, Grant { by: 0, t: 0, holder: 1, role: Role::Write, until: None, may_grant: true, flow: true }, Sync { from: 0, to: 1 }, tick.clone(), Grant { by: 1, t: 0, holder: 2, role: Role::Write, until: None, may_grant: false, flow: true }, Sync { from: 1, to: 2 }, tick.clone(), Write { by: 2, t: 0, op: 0, k: 0, v: 1 }],
            orders: None,
        },
    ]
}

/// May-grant grants the granter's path does not cover (spec/permissions.md §2, §5.1): bare edge
/// writes, which the writer's checks refuse, except where the granter did not know yet. In each,
/// 0 removed 2 and gave 1 a grant with the may-grant flag first.
fn may_grants() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    let start = |role: Role| vec![Edge { by: 0, t: 0, holder: 2, role: None }, Grant { by: 0, t: 0, holder: 1, role, until: None, may_grant: true, flow: false }, Sync { from: 0, to: 1 }, tick.clone()];
    let then = |base: Vec<Step>, more: Vec<Step>| base.into_iter().chain(more).collect::<Vec<_>>();
    let w2 = HostileWrite { by: 2, t: 0, v: 1 };
    vec![
        Scenario {
            name: "may-grant grant with a role above the granter's",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 1 (read, may-grant) grants 2 write: not applied, 2's write invalid",
            steps: then(start(Role::Read), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), may_grant: false }, Sync { from: 1, to: 2 }, tick.clone(), w2.clone()]),
            orders: None,
        },
        Scenario {
            name: "may-grant grant within the granter's role, control",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 1 (read, may-grant) grants 2 read: applied, with no boxes (the edge is judged on its own); 2's write invalid (read)",
            steps: then(start(Role::Read), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Read), may_grant: false }, Sync { from: 1, to: 2 }, tick.clone(), w2.clone()]),
            orders: None,
        },
        Scenario {
            name: "may-grant grant over a current edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2 holds read; 1 (write, may-grant) writes 2's edge to write: may-grant adds edges only, not applied",
            steps: then(start(Role::Write), vec![Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), may_grant: false }]),
            orders: None,
        },
        Scenario {
            name: "may-grant grant over an expired edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2's read edge ended by `until`; 1 (write, may-grant) grants 2 write: an expired edge counts as none, applied",
            steps: then(start(Role::Write), vec![Grant { by: 0, t: 0, holder: 2, role: Role::Read, until: Some(500), may_grant: false, flow: false }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), may_grant: false }]),
            orders: None,
        },
        Scenario {
            name: "a holder by may-grant removes another edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2 holds read; 1 (write, may-grant) removes 2's edge: holders by may-grant change no other edge, not applied",
            steps: then(start(Role::Write), vec![Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: None, may_grant: false }]),
            orders: None,
        },
        // §5.1 step 3: a lowering clearing the flag puts the grants made by it in question
        Scenario {
            name: "may-grant grant unseen by the granter's removal",
            spec: "spec/permissions.md §5.1, §7",
            source: "hand-picked: 1 (write, may-grant) grants 2 write, unseen by 0; 0 removes 1 with its frontier: the grant goes to D",
            steps: then(start(Role::Write), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), may_grant: false }, tick.clone(), Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false }]),
            orders: None,
        },
        Scenario {
            name: "may-grant grant seen by the granter's removal",
            spec: "spec/permissions.md §5.1, §7",
            source: "hand-picked: 1 (write, may-grant) grants 2 write and 0 receives it; 0 removes 1 with its frontier: the grant stands",
            steps: then(start(Role::Write), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), may_grant: false }, Sync { from: 1, to: 0 }, tick.clone(), Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false }]),
            orders: None,
        },
        // §2: a grant past its signer's may-grant gets no exemption for its `secrets.0`
        Scenario {
            name: "may-grant grant through the flow after the flag went",
            spec: "spec/permissions.md §2, §5.1, §5.2",
            source: "hand-picked: 1 holds read with may-grant; 0 rewrites it to read without, unseen by 1, which grants 2 read through the flow: the edge is not applied and its `secrets.0` delta, no longer exempt, needs write: invalid",
            steps: vec![Edge { by: 0, t: 0, holder: 2, role: None }, Edge { by: 0, t: 0, holder: 1, role: None }, Grant { by: 0, t: 0, holder: 1, role: Role::Read, until: None, may_grant: true, flow: true }, Sync { from: 0, to: 1 }, tick.clone(), Grant { by: 0, t: 0, holder: 1, role: Role::Read, until: None, may_grant: false, flow: false }, tick.clone(), Grant { by: 1, t: 0, holder: 2, role: Role::Read, until: None, may_grant: false, flow: true }],
            orders: None,
        },
    ]
}

/// A write given back (spec/permissions.md §5.2, spec/crdt.md §4.6): 1 puts an entry, 2 (sent it
/// alone) writes inside it and compacts, 0 holds 2's commits, writes inside it too and compacts;
/// 0 lowers 2 to read, so 2's delta and snapshot give nothing. A node without 1's commit then holds the
/// entry's creation through nothing, until 0's valid snapshot or 1's commit gives it back.
fn remerges() -> Vec<Scenario> {
    use Step::*;
    fn orders(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
        // 1's put, 2's write, 2's snapshot, 0's write, 0's snapshot, 0's demotion of 2
        let at = |c: usize| of.iter().position(|x| *x == played.base + c).unwrap();
        let setup: Vec<Tok> = (0..at(0)).map(Tok::In).collect();
        let list = |cs: &[usize]| setup.iter().copied().chain(cs.iter().map(|c| Tok::In(at(*c)))).collect();
        vec![
            ("as made", list(&[0, 1, 2, 3, 4, 5])),
            ("without what gives it back", list(&[1, 2, 3, 5])),
            ("given back by a valid snapshot", list(&[1, 2, 3, 5, 4])),
            ("given back by the creating commit", list(&[1, 2, 3, 5, 0])),
        ]
    }
    vec![Scenario {
        name: "re-merge of an entry's creation",
        spec: "spec/permissions.md §5.2, spec/crdt.md §4.6",
        source: "order harness histories, simplified by hand",
        steps: vec![NestedTyped { by: 1, other: 2, t: 0, k: 2 }, Sync { from: 2, to: 0 }, TypedField { by: 0, t: 0, k: 2, v: 3 }, Compact { by: 0, t: 0, op: 3 }, Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }],
        orders: Some(orders),
    }]
}

/// One history over two sync IDs (`lay`'s `second`): one commit, a part under each. H's mint admin
/// is 0, so only H's own edge gives 1 a role on it.
fn sync_ids() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    /// The entries before the last commit (its parts span both sync IDs, `two`) that come after
    /// the setup, and the setup.
    fn entries(played: &Played, of: &[usize]) -> (Vec<usize>, Vec<Tok>, Vec<usize>) {
        let b = played.base;
        let two: Vec<usize> = (0..of.len()).filter(|e| of[*e] == played.packs.len() - 1).collect();
        assert_eq!(two.len(), 2, "a part under each sync ID");
        let k = of.iter().position(|x| *x == b).unwrap();
        ((k..two[0]).collect(), (0..k).map(Tok::In).collect(), two)
    }
    fn orders(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
        let (c, setup, two) = entries(played, of);
        let list = |post: &[usize]| setup.iter().copied().chain(c.iter().chain(post).map(|e| Tok::In(*e))).collect();
        vec![("both sync IDs", list(&two)), ("one sync ID", list(&two[..1]))]
    }
    /// The two parts in both orders, before or after the rest, and the withheld edge last.
    fn chainless(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
        let (rest, two, edges) = chainless_entries(played, of);
        let list = |post: &[usize]| rest.iter().chain(post).map(|e| Tok::In(*e)).collect::<Vec<Tok>>();
        let (gh, hg) = ([two[0], two[1]], [two[1], two[0]]);
        let early = |parts: &[usize]| parts.iter().chain(&rest).map(|e| Tok::In(*e)).collect::<Vec<Tok>>();
        let (gh_e, hg_e): (Vec<usize>, Vec<usize>) = (gh.iter().chain(&edges).copied().collect(), hg.iter().chain(&edges).copied().collect());
        vec![
            ("G first", list(&gh)),
            ("H first", list(&hg)),
            // the parts before the rest
            ("parts first, G first", early(&gh)),
            ("parts first, H first", early(&hg)),
            ("G first, the edge last", list(&gh_e)),
            ("H first, the edge last", list(&hg_e)),
        ]
    }
    vec![
        Scenario {
            name: "content commit over two sync IDs",
            spec: "spec/commits.md §4, spec/sync-judgement.md §1",
            source: "hand-built: 1 writes both G (it holds write) and H (it holds read) in one commit: each delta judged alone; nothing waits for a part",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Two { by: 1, a: 0, b: 1, v: 1 }],
            orders: Some(orders),
        },
        Scenario {
            name: "role commit over two sync IDs",
            spec: "spec/commits.md §4, spec/permissions.md §5.1",
            source: "hand-built: 0 grants 1 read on both G and H in one role commit: a role commit never waits for its other deltas",
            steps: vec![NewTop { by: 0 }, tick.clone(), TwoEdges { by: 0, a: 0, b: 1, holder: 1, role: Role::Read }],
            orders: Some(orders),
        },
        Scenario {
            name: "content commit, its path to H away",
            spec: "spec/commits.md §4, spec/requirements.md Decentralization",
            source: "hand-built: 1 writes both G and H, the edge giving it a path to H withheld: H's part waits alone in either order; the edge arriving ends as in order",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Two { by: 1, a: 0, b: 1, v: 1 }],
            orders: Some(chainless),
        },
        Scenario {
            name: "role commit, its path to H away",
            spec: "spec/commits.md §4, spec/requirements.md Decentralization",
            source: "hand-built: 2 (admin on G) sets 1's edge on G and H, the edge giving it a path to H withheld: G's roster changes in either order",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 2 }, tick.clone(), TwoEdges { by: 2, a: 0, b: 1, holder: 1, role: Role::Read }],
            orders: Some(chainless),
        },
    ]
}

/// A history whose commit after the setup is the edge giving the last commit's author its path to
/// H, and whose last commit has a part under each sync ID: (the entries of every other commit,
/// the last commit's two, the edge's).
fn chainless_entries(played: &Played, of: &[usize]) -> (Vec<usize>, [usize; 2], Vec<usize>) {
    let (edge, last) = (played.base + 1, played.packs.len() - 1);
    let rest = (0..of.len()).filter(|e| of[*e] != edge && of[*e] != last).collect();
    let two: Vec<usize> = (0..of.len()).filter(|e| of[*e] == last).collect();
    let edges = (0..of.len()).filter(|e| of[*e] == edge).collect();
    (rest, two.try_into().expect("a part under each sync ID"), edges)
}

/// Referenced blobs: as made, and the setup first with the rest reversed (blobs after what names
/// them) and without the blobs.
fn refs_orders(played: &Played, of: &[usize], refs: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
    let mut o = default_orders(played, of, refs);
    o.push(("without its blobs", (0..of.len()).filter(|e| !refs.contains(e)).map(Tok::In).collect()));
    o
}

/// For writes then `LinkedDemote`: the setup, the writes, the demotion without its frontier's
/// blobs, with them last and first.
fn linked_orders(played: &Played, of: &[usize], refs: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
    let setup: Vec<Tok> = (0..of.len()).filter(|e| of[*e] < played.base).map(Tok::In).collect();
    let body_of = |c: usize| (0..of.len()).find(|e| of[*e] == c && !refs.contains(e)).unwrap();
    let last = played.packs.len() - 1;
    let write: Vec<Tok> = (played.base..last).map(|c| Tok::In(body_of(c))).collect();
    let demotion = [Tok::In(body_of(last))];
    let blobs: Vec<Tok> = refs.iter().map(|e| Tok::In(*e)).collect();
    let cat = |xs: &[&[Tok]]| xs.concat();
    vec![
        ("without the frontier's blobs", cat(&[&setup, &write, &demotion])),
        ("the frontier's blobs last", cat(&[&setup, &write, &demotion, &blobs])),
        ("the frontier's blobs first", cat(&[&setup, &blobs, &write, &demotion])),
    ]
}

/// A history of one body and what it references: its bodies alone, in the order made.
fn bodies_only(_: &Played, of: &[usize], refs: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
    vec![("as made", (0..of.len()).filter(|e| !refs.contains(e)).map(Tok::In).collect())]
}

/// A history of one body and what it references: only the order it was made in.
fn made_only(_: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
    vec![("as made", (0..of.len()).map(Tok::In).collect())]
}

/// Commits that reference blobs: a paged delta, a large atomic value, a linked frontier.
fn blobs() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    vec![
        Scenario {
            name: "paged delta",
            spec: "spec/commits.md §4, spec/crdt.md §8",
            source: "hand-picked: 1 writes a map above PAGE_TARGET: the commit waits for its pages, then applies",
            steps: vec![Paged { by: 1, t: 0 }],
            orders: Some(refs_orders),
        },
        Scenario {
            name: "large atomic value",
            spec: "spec/commits.md §4, spec/data-model.md §6",
            source: "hand-picked: 1 writes a value above CHUNK_THRESHOLD; the entries leave out its chunks, which nothing waits for: the commit applies",
            steps: vec![Large { by: 1, t: 0 }],
            orders: Some(made_only),
        },
        // the demotion's blobs are never delivered: it only waits here
        Scenario {
            name: "demotion with a linked frontier, its blobs not held",
            spec: "spec/commits.md §4, spec/wire.md §4",
            source: "hand-picked: 0 removes 1 with a frontier above CHUNK_THRESHOLD: the commit waits for the blobs, 1 stays",
            steps: vec![LinkedDemote { by: 0, t: 0, holder: 1 }],
            orders: Some(bodies_only),
        },
        Scenario {
            name: "frontier coverage with a linked frontier",
            spec: "spec/commits.md §4, spec/permissions.md §5.1",
            source: "hand-picked: W by 1 reaches 0, W' does not; 0 removes 1 with a frontier above CHUNK_THRESHOLD; the demotion waits for the frontier's blobs, then the frontier keeps W valid, W' invalid",
            steps: vec![Write { by: 1, t: 0, op: 1, k: 0, v: 1 }, Sync { from: 1, to: 0 }, tick.clone(), Write { by: 1, t: 0, op: 1, k: 0, v: 2 }, tick.clone(), LinkedDemote { by: 0, t: 0, holder: 1 }],
            orders: Some(linked_orders),
        },
    ]
}

/// Keep bounds and expiry: dead purge-on-replace bodies dropped where they die and held where
/// they do not, and expired puts.
fn bounds() -> Vec<Scenario> {
    use Step::*;
    vec![
        Scenario {
            name: "purge-on-replace snapshot of an undone write",
            spec: "spec/commits.md §5",
            source: "order harness, shrunk: B's purge-on-replace snapshot carries A's write that A's undo (lower `ts`) killed",
            steps: vec![Write { by: 0, t: 1, op: 18, k: 1, v: 6 }, Send { from: 0, to: 1, back: 0 }, Undo { by: 0, back: 0 }, Compact { by: 1, t: 0, op: 18 }, Write { by: 0, t: 0, op: 18, k: 0, v: 5 }],
            orders: None,
        },
        Scenario {
            name: "purge-on-replace writes of one ts",
            spec: "spec/commits.md §5, spec/crdt.md §4.8",
            source: "order harness, shrunk: two purge-on-replace writes with one `ts`, the later by commit ID wins; its author demoted",
            steps: vec![Write { by: 2, t: 4, op: 18, k: 2, v: 4 }, Write { by: 1, t: 6, op: 18, k: 1, v: 4 }, Demote { by: 0, t: 4, holder: 2, at: 3, to_read: false }],
            orders: None,
        },
        Scenario {
            name: "purge-on-replace body whose own write turns invalid",
            spec: "spec/commits.md §5",
            source: "order harness, shrunk: a purge-on-replace body (bound 30 min) whose own write turns invalid, the bound passed",
            steps: vec![Demote { by: 0, t: 7, holder: 1, at: 5, to_read: true }, Write { by: 1, t: 5, op: 17, k: 0, v: 1 }, Write { by: 0, t: 5, op: 17, k: 0, v: 5 }, Advance { who: None, ms: 5183786 }],
            orders: None,
        },
        Scenario {
            name: "purge-on-replace snapshot of an entry an earlier-stamped undo killed",
            spec: "spec/commits.md §5",
            source: "order harness, shrunk: A's purge-on-replace snapshot carries B's entry, which B's undo stamped before it killed; A's demotion of B makes the undo invalid",
            steps: vec![Write { by: 1, t: 1, op: 19, k: 0, v: 1 }, Sync { from: 1, to: 0 }, Compact { by: 1, t: 4, op: 0 }, Undo { by: 1, back: 1 }, Advance { who: None, ms: 6766743 }, Compact { by: 0, t: 0, op: 20 }, Demote { by: 0, t: 6, holder: 1, at: 1, to_read: false }],
            orders: None,
        },
        Scenario {
            name: "expired map puts",
            spec: "spec/crdt.md §4.7",
            source: "order harness, shrunk: two expired map puts",
            steps: vec![Write { by: 1, t: 7, op: 28, k: 1, v: 6 }, Write { by: 1, t: 2, op: 28, k: 1, v: 2 }, Advance { who: None, ms: 4563278 }],
            orders: None,
        },
    ]
}

/// Replays every case of a file (its inputs only) and compares the expected fields.
fn replay_file(path: &str, text: &str) -> Result<usize, String> {
    replay_cases(path, text, None)
}

/// `replay_file` of the case named `only`, or all of them.
fn replay_cases(path: &str, text: &str, only: Option<&str>) -> Result<usize, String> {
    let f = VecFile::parse(text).map_err(|e| format!("{path}: {e}"))?;
    let setup = osis_base::hex::decode(f.header.req("setup")?).ok_or_else(|| format!("{path}: bad setup hex"))?;
    // the header's expected lines: part of every case's judgment
    let shared: Vec<(String, String)> = f.header.fields.iter().filter(|(k, _)| !HEADER.contains(&k.as_str())).cloned().collect();
    let mut laid: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for c in f.live() {
        let name = c.req("case")?;
        let e = c.req("entries")?;
        let bytes = match e.strip_prefix("as in ") {
            Some(other) => laid.get(other).cloned().ok_or_else(|| format!("{name}: no case {other}"))?,
            None => [&setup[..], &osis_base::hex::decode(e).ok_or_else(|| format!("{name}: bad entries hex"))?].concat(),
        };
        laid.insert(name.to_string(), bytes.clone());
        if only.is_some_and(|x| x != name) {
            continue;
        }
        let mut reads = Vec::new();
        for x in c.req("read-secret")?.split(',') {
            let b = osis_base::hex::decode(x).ok_or("bad read-secret")?;
            reads.push(Secret32::from_bytes(b.try_into().map_err(|_| "read-secret length")?));
        }
        let now = Time(c.req("now")?.parse().map_err(|_| "bad now")?);
        let mut got = judged(&bytes, setup.len(), &reads, now, &parse_order(c.req("order")?));
        if let Some(f) = shared.iter().find(|f| !got.contains(f)) {
            return Err(format!("{path}, case `{name}`: judged no `{}: {}` (a header line)", f.0, f.1));
        }
        got.retain(|f| !shared.contains(f));
        let want: Vec<(String, String)> = c.fields.iter().filter(|(k, _)| !INPUTS.contains(&k.as_str())).cloned().collect();
        if got != want {
            let first = got.iter().zip(&want).find(|(g, w)| g != w).map(|(g, w)| format!("want `{}: {}`, got `{}: {}`", w.0, w.1, g.0, g.1)).unwrap_or_else(|| format!("{} fields expected, {} judged", want.len(), got.len()));
            return Err(format!("{path}, case `{name}`: {first}"));
        }
    }
    Ok(f.live().count())
}

/// Every case of judgment file `name` has its inputs and entries that parse, and replayed from
/// its text judges as generated (each input judged once by a fresh engine: `judged`).
fn vectors(name: &str) {
    let (path, text) = file(name);
    osis_vectors::subjects::judgment::check(&VecFile::parse(&text).unwrap()).unwrap_or_else(|e| panic!("{path}: {e}"));
    let n = replay_file(&path, &text).unwrap_or_else(|e| panic!("{e}"));
    assert!(n > 0, "{path}: no cases");
}

// spec/permissions.md §5.1, §5.2: the judgment vectors (core/test/vectors/README.md,
// `judgment/`) of models.vec, the roles model's reference scenarios (`vectors`).
#[test]
fn judgment_vectors_models_spec_permissions_5_2() {
    vectors("models");
}

// spec/permissions.md §3, §5.1, §5.2, spec/commits.md §5, spec/crdt.md §4.6: the judgment
// vectors of rules.vec, one scenario per rule family (`vectors`).
#[test]
fn judgment_vectors_rules_spec_permissions_5_2() {
    vectors("rules");
}

// spec/permissions.md §2, §5.1, §5.2, §7: the judgment vectors of edges.vec, an edge's `until`
// and may-grant (`vectors`).
#[test]
fn judgment_vectors_edges_spec_permissions_5_1() {
    vectors("edges");
}

// spec/permissions.md §5.2, spec/commits.md §5, spec/crdt.md §4.6, §4.7, §4.8: the judgment
// vectors of bounds.vec, a re-merge, keep bounds and expiry (`vectors`).
#[test]
fn judgment_vectors_bounds_spec_commits_5() {
    vectors("bounds");
}

// spec/commits.md §4, spec/sync-judgement.md §1, spec/permissions.md §5.1: the judgment vectors
// of sync IDs.vec, commits with bodies under two sync IDs (`vectors`).
#[test]
fn judgment_vectors_sync_ids_spec_commits_4() {
    vectors("sync IDs");
}

// spec/commits.md §4, spec/crdt.md §8, spec/data-model.md §6, spec/wire.md §4, spec/permissions.md
// §5.1: the judgment vectors of blobs.vec, blobs a commit references (`vectors`).
#[test]
fn judgment_vectors_blobs_spec_commits_4() {
    vectors("blobs");
}

// spec/requirements.md Decentralization, spec/commits.md §4: one held set, its parts in two
// orders, the edge giving the author its path to H withheld: 1 (write on G and H) writes both,
// the H part waiting alone either way and G's write standing; 2 (admin on G, a write edge on H)
// sets 1's edge on G and H, either order changing G's roster. The node shows the same in both.
#[test]
fn chainless_part_order_spec_commits_4() {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    for (by, last) in [(1, Two { by: 1, a: 0, b: 1, v: 1 }), (2, TwoEdges { by: 2, a: 0, b: 1, holder: 1, role: Role::Read })] {
        let played = play(0, &[NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: by, role: Some(Role::Write) }, Sync { from: 0, to: by }, tick.clone(), last.clone()]);
        let laid = lay(&played, true);
        let (rest, [g, h], _) = chainless_entries(&played, &laid.of);
        let judge = |parts: [usize; 2]| replay(&laid.bytes, laid.setup, &read_secrets(true), played.now, &rest.iter().chain(&parts).map(|e| Tok::In(*e)).collect::<Vec<_>>());
        assert_eq!(judge([g, h]), judge([h, g]), "{last:?}");
    }
}

// spec: none (a check of the judgment vectors): in every case, flipping its first own verdict
// makes the replay report that case; in some case of every file, so does dropping the last step
// of its order (a step a user cannot see, such as a commit that waits or is refused, leaves the
// judgment alone).
#[test]
#[ignore = "by hand: the vectors' negative control"]
fn judgment_vectors_can_fail() {
    for (path, text) in files() {
        let mut shown = false;
        let f = VecFile::parse(&text).unwrap();
        for c in f.live() {
            let name = c.req("case").unwrap();
            let in_case = |key: &str, new: &str| -> String {
                let at = text.find(&format!("case: {name}\n")).unwrap();
                let line = text[at..].find(&format!("\n{key}: ")).unwrap() + at + 1;
                let end = text[line..].find('\n').unwrap() + line;
                format!("{}{key}: {new}{}", &text[..line], &text[end..])
            };
            let own = c.fields.iter().find(|(k, _)| !INPUTS.contains(&k.as_str())).unwrap_or_else(|| panic!("{name}: no own line"));
            let flip = if own.1.contains("unapplied") { own.1.replace("unapplied", "applied") } else if own.1.contains("invalid") { own.1.replace("invalid", "valid") } else { format!("{} x", own.1) };
            let e = replay_cases(&path, &in_case(&own.0, &flip), Some(name)).expect_err(&format!("{name}: a changed verdict passes"));
            assert!(e.contains(name), "{e}");
            let order = c.req("order").unwrap();
            let shorter = &order[..order.rfind(',').unwrap()];
            if let Err(e) = replay_cases(&path, &in_case("order", shorter), Some(name)) {
                assert!(e.contains(name), "{e}");
                shown = true;
            }
        }
        assert!(shown, "{path}: no case's order shows");
    }
}
