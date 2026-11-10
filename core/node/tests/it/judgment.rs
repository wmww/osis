//! Judgment conformance vectors (core/test/vectors/README.md, `judgment/`): histories played by
//! the order harness (`order::play`), carried in a bundle as one label's host holds them, judged
//! by a fresh node in a given arrival order; the expected verdicts are what this engine judges.
//! `judgment_vectors_spec_permissions_5_2` replays every generated case (its inputs only) through
//! a fresh engine and compares; `judgment_vectors_can_fail` (ignored) checks a changed verdict
//! fails each case, and a shorter order some case of each file.

use crate::order::{Played, Step, play};
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, label_role_key};
use osis_label::{BundleReader, BundleWriter, Importer, Parent, Record, StepKeys, genesis_label, register, sign_stamp};
use osis_node::local_peer::Peer;
use osis_vectors::file::{Record as Rec, VecFile};
use std::collections::{BTreeMap, BTreeSet};

/// The judging node's rng seed (its own identity is never observed).
const FRESH: u64 = 0x5eed_f00d;
/// Every history's peers: one seed, so a file's bundles share their setup (the header's `setup`).
const SEED: u64 = 1038;
/// Fields of a case that are inputs; every other field is expected output.
const INPUTS: [&str; 7] = ["case", "spec", "source", "read-secret", "now", "bundle", "order"];
/// Header fields that are not expected lines.
const HEADER: [&str; 4] = ["subject", "spec", "source", "setup"];
const GEN: &str = "osis-node judgment generator (tests/it/judgment.rs)";

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One arrival step: receive bundle entry i (a body it opens, else a referenced blob), advance
/// the clock by ms and run timers, drop every aspect of entry i's body as covered (node-sync's
/// compaction drop), or start syncing a thing.
#[derive(Clone, Copy, Debug)]
enum Tok {
    In(usize),
    Wait(u64),
    Drop(usize),
    Sync(Tid),
}

fn render_order(o: &[Tok]) -> String {
    o.iter().map(|t| match t {
        Tok::In(i) => i.to_string(),
        Tok::Wait(ms) => format!("+{ms}"),
        Tok::Drop(i) => format!("d{i}"),
        Tok::Sync(t) => format!("s{t}"),
    }).collect::<Vec<_>>().join(",")
}

fn parse_order(s: &str) -> Vec<Tok> {
    s.split(',').map(|t| match (t.strip_prefix('+'), t.strip_prefix('d'), t.strip_prefix('s')) {
        (Some(ms), ..) => Tok::Wait(ms.parse().unwrap()),
        (_, Some(i), _) => Tok::Drop(i.parse().unwrap()),
        (_, _, Some(x)) => Tok::Sync(x.parse().unwrap()),
        _ => Tok::In(t.parse().unwrap()),
    }).collect()
}

/// One label of a bundle: its genesis path record, stamp key and read secret.
struct Lab {
    path: Record,
    id: osis_base::LabelId,
    read: Secret32,
    stamp: osis_crypto::SigningSecret,
}

/// A label's genesis path from group secrets all but the deposit seed named `base`: read
/// `base`, write `base + 1`, admin `base - 1`, deposit seed `base + 2`.
fn label(base: u8, rng: &mut SeededRng) -> Lab {
    let (r, w, a) = (s32(base), s32(base + 1), s32(base - 1));
    let id = genesis_label(&a, 0);
    let keys = StepKeys::derive(&r, &w, &a, 0, &s32(base + 2), &id);
    let delete = label_role_key(LabelRole::Delete, &a, 0);
    let (step, claims) = register(Parent::Genesis(&delete), keys, &[], (&Tid::from_bytes([base - 3; 15]), Epoch::new(0, [0; 32]).unwrap(), &r), rng).unwrap();
    Lab { id: step.label, path: Record::Path { label: step.label, steps: vec![(step, Some(claims))] }, read: r, stamp: label_role_key(LabelRole::Write, &w, 0) }
}

/// What `bundle` lays out: the bytes, each entry's commit index, the entries that are referenced
/// blobs and the length of the setup's prefix.
struct Laid {
    bytes: Vec<u8>,
    of: Vec<usize>,
    refs: BTreeSet<usize>,
    setup: usize,
}

/// A played history as a bundle as the hosts hold it: the genesis path of the first label (group
/// secrets read `0a`, write `0b`, admin `09`, deposit seed `0c`), then per commit the blobs it
/// references, each under a filler wrap (left out where the case needs no bytes of them: the
/// chunks of `t:blob.0`, which nothing waits for), and its
/// one blob (sections per label, each under that label's read secret, spec/wire.md §4) sealed
/// and stamped under every label with a part of it, each blob before its entry. With `second`,
/// every thing but G is under a second label (read `1a`, write `1b`, admin `19`, deposit seed
/// `1c`), its path before its first entry.
fn bundle(played: &Played, second: bool) -> Laid {
    let mut rng = SeededRng::from_u64(0x0b0d1e);
    let first = label(0x0a, &mut rng);
    let mut recs = vec![first.path.clone()];
    let mut of = Vec::new();
    let mut refs = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut other: Option<Lab> = None;
    let mut setup = 1;
    for (ci, pk) in played.packs.iter().enumerate() {
        let cb = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        // bare headers name no list by link in these histories: the aspects are at hand
        let under = |ai: usize| second && cb.header.aspects[ai].tid != played.things[0] && played.things.contains(&cb.header.aspects[ai].tid);
        let readers: Vec<bool> = cb.parts.iter().map(|p| under(p.ai)).collect::<BTreeSet<_>>().into_iter().collect();
        if readers.contains(&true) && other.is_none() {
            let l = label(0x1a, &mut rng);
            recs.push(l.path.clone());
            other = Some(l);
        }
        let lab_of = |second: bool| if second { other.as_ref().unwrap() } else { &first };
        // the referenced blobs under the first label the commit has a part under
        if let Some(r0) = readers.first().copied()
            && !cb.header.aspects.iter().any(|a| a.ak.as_str() == "t:blob.0")
        {
            let lab = lab_of(r0);
            for (id, b) in &pk.blobs {
                if seen.insert(*id) {
                    let wrap = osis_crypto::filler_wrap(&mut rng);
                    let stamp = sign_stamp(&lab.stamp, &lab.id, id, &wrap);
                    recs.push(Record::Blob(b.clone()));
                    recs.push(Record::Entry { label: lab.id, blob: *id, wrap, stamp: Some(stamp) });
                    refs.insert(of.len());
                    of.push(ci);
                }
            }
        }
        if !cb.parts.is_empty() {
            let env = osis_commit::seal_commit(&cb, under, |r, _| Some((lab_of(*r).read.clone(), vec![])), &[], &mut rng).unwrap();
            let sealed = osis_node::labeling::frame_envelope(&env, &cb.header, osis_label::Class::Durable, &mut rng, &cb).unwrap();
            recs.push(Record::Blob(sealed.blob));
            for r in readers {
                let lab = lab_of(r);
                let wrap = osis_crypto::wrap(&lab.read, &sealed.id, &sealed.key, 1).unwrap();
                let stamp = sign_stamp(&lab.stamp, &lab.id, &sealed.id, &wrap);
                recs.push(Record::Entry { label: lab.id, blob: sealed.id, wrap, stamp: Some(stamp) });
                of.push(ci);
            }
        }
        if ci < played.base {
            setup = recs.len();
        }
    }
    let write = |recs: &[Record]| {
        let mut bw = BundleWriter::new(Vec::new()).unwrap();
        for x in recs {
            bw.record(x).unwrap();
        }
        bw.finish().unwrap()
    };
    let (full, setup) = (write(&recs), write(&recs[..setup]));
    assert!(full.starts_with(&setup), "a bundle is its records' frames in order");
    Laid { bytes: full, of, refs, setup: setup.len() }
}

/// Reads a bundle as an importer does (paths and stamps verified): its entries in order, each
/// with its blob.
fn entries(bytes: &[u8]) -> Vec<(osis_base::BlobId, [u8; osis_crypto::WRAP_LEN], Vec<u8>)> {
    let mut rd = BundleReader::new(bytes).unwrap();
    let mut imp = Importer::new();
    let mut blobs = BTreeMap::new();
    let mut out = Vec::new();
    while let Some(r) = rd.next_record().unwrap() {
        imp.import(r.clone()).unwrap().unwrap();
        match r {
            Record::Blob(b) => {
                blobs.insert(osis_label::blob_id(&b), b);
            }
            Record::Entry { blob, wrap, .. } => out.push((blob, wrap, blobs[&blob].clone())),
            _ => {}
        }
    }
    out
}

fn role(r: Role) -> &'static str {
    match r {
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
    }
}

fn hash_hex(b: &[u8]) -> String {
    osis_base::hex::encode(&osis_base::hash::hash(b))
}

/// Delivers `order` of the bundle's entries to a fresh node at `now`; what it judges, as the
/// expected fields of a case (README.md, `judgment/`).
fn replay(bytes: &[u8], reads: &[Secret32], now: WallMs, order: &[Tok]) -> Vec<(String, String)> {
    let ents = entries(bytes);
    let mut p = Peer::new(FRESH, now).unwrap();
    let mut ids = BTreeSet::new();
    // a filler wrap opens under no read secret (spec/crypto.md §5)
    // an entry delivers its label's section: the one sealed under the read secret its wrap
    // opened with (a node holding one label's secret reads that label's parts)
    let open = |i: usize| {
        let (id, wrap, blob) = &ents[i];
        osis_label::unwrap_any(reads, id, wrap).map(|(ri, key)| {
            let (_, pt) = osis_label::open(blob, &key).unwrap();
            let env = osis_commit::Envelope::decode(&pt).unwrap();
            let o = env.open(|_| vec![reads[ri].clone()]).unwrap();
            (o.commit.encode(), o.commit)
        })
    };
    for t in order {
        match *t {
            Tok::In(i) => match open(i) {
                Some((pt, cb)) => {
                    ids.insert(cb.id());
                    let _ = p.engine.ingest(&pt, Vec::new());
                }
                None => {
                    p.engine.put_blobs(vec![(ents[i].0, ents[i].2.clone())]).unwrap();
                    p.reexamine().unwrap();
                }
            },
            Tok::Sync(t) => p.engine.set_syncing(t, true).unwrap(),
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
    // cover fell) is fetched where present (spec/sync.md §6): every body entry received comes again
    for t in order {
        if let Tok::In(i) = *t
            && let Some((pt, _)) = open(i)
        {
            let _ = p.engine.ingest(&pt, Vec::new());
        }
    }
    p.reexamine().unwrap();
    observe(&mut p.engine, &ids)
}

/// What a node holding `ids` shows of them, as a user could see it: each held part's validity (or
/// its edge write applied in the walk), each touched thing's roster and each touched aspect's read.
pub(crate) fn observe(e: &mut osis_node::Engine, ids: &BTreeSet<CommitId>) -> Vec<(String, String)> {
    let hex = |c: &CommitId| osis_base::hex::encode(&c.0);
    let mut held: Vec<(osis_base::Ts, CommitId)> = ids.iter().filter_map(|c| e.header(c).map(|h| (h.ts, *c))).collect();
    held.sort();
    let mut out = Vec::new();
    let mut things = BTreeSet::new();
    let mut aspects = BTreeSet::new();
    for (_, c) in &held {
        let h = e.header(c).unwrap();
        for a in &h.aspects {
            things.insert(a.tid);
            aspects.insert((a.tid, a.ak.clone()));
            // an edge write has no content verdict: it applies in the walk or not (§5.1)
            let valid = match a.ak.as_str() {
                "roles.0" if e.edge_write_applied(&a.tid, c) => "applied",
                "roles.0" => "unapplied",
                _ if e.body_valid(c, &a.tid, &a.ak).unwrap() => "valid",
                _ => "invalid",
            };
            out.push((format!("body {} {} {}", hex(c), a.tid, a.ak.as_str()), valid.to_string()));
        }
    }
    for t in &things {
        let roster: Vec<String> = e.roster(t).iter().map(|(h, ed)| {
            let mut s = format!("{h}:{}", role(ed.role));
            if let Some(u) = ed.until {
                s += &format!(":until={}", u.0);
            }
            if let Some(i) = ed.invite {
                s += &format!(":invite={}", role(i));
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

/// `second`: every thing but G under a second label (`bundle`).
fn generate(spec: &str, scenarios: Vec<Scenario>, second: bool) -> VecFile {
    let mut setup: Option<Vec<u8>> = None;
    let mut cases = Vec::new();
    let reads = read_secrets(second);
    let reads_hex = reads.iter().map(|x| osis_base::hex::encode(x.expose())).collect::<Vec<_>>().join(",");
    for sc in scenarios {
        let played = play(SEED, &sc.steps);
        let laid = bundle(&played, second);
        let n = laid.setup;
        assert_eq!(setup.get_or_insert_with(|| laid.bytes[..n].to_vec())[..], laid.bytes[..n], "{}: one setup per file", sc.name);
        let orders = sc.orders.unwrap_or(default_orders)(&played, &laid.of, &laid.refs);
        let first = format!("{}, {}", sc.name, orders[0].0);
        for (i, (oname, order)) in orders.into_iter().enumerate() {
            let name = format!("{}, {oname}", sc.name);
            let mut r = Rec::new().with("case", &name).with("spec", sc.spec).with("source", sc.source).with("read-secret", &reads_hex).with("now", played.now.0.to_string());
            r = if i == 0 { r.with("bundle", osis_base::hex::encode(&laid.bytes[n..])) } else { r.with("bundle", format!("as in {first}")) };
            r = r.with("order", render_order(&order));
            for (k, v) in replay(&laid.bytes, &reads, played.now, &order) {
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

/// The judgment files (`judgment/<name>.vec`, never written out), generated in memory.
fn files() -> Vec<(&'static str, String)> {
    vec![
        ("judgment/models.vec", generate("spec/permissions.md §5", models(), false).render()),
        ("judgment/rules.vec", generate("spec/permissions.md §2, §5, spec/commits.md §5, spec/crdt.md §4", rules().into_iter().chain(edges()).chain(invites()).chain(remerges()).chain(bounds()).collect(), false).render()),
        ("judgment/labels.vec", generate("spec/commits.md §4, spec/sync.md §3, spec/wire.md §12", labels(), true).render()),
        ("judgment/blobs.vec", generate("spec/commits.md §4, spec/crdt.md §8, spec/permissions.md §5.1", blobs(), false).render()),
    ]
}

/// The roles model's pinned reference scenarios played on the engine (core/test/roles-model):
/// peer 0 is G's first admin, 1 writes, 2 is admin (`order::play`'s setup).
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
            source: "roles-model content::frontier_decides_pre_revoke_edits (unseen: both invalid)",
            steps: vec![w(1, 1), tick.clone(), revoke.clone(), tick.clone(), w(1, 2)],
            orders: None,
        },
        Scenario {
            name: "pre-revoke edit seen by the revoker",
            spec: "spec/permissions.md §5.1, §5.2",
            source: "roles-model content::frontier_decides_pre_revoke_edits (seen: the first stands)",
            steps: vec![w(1, 1), Sync { from: 1, to: 0 }, tick.clone(), revoke.clone(), tick.clone(), w(1, 2)],
            orders: None,
        },
        Scenario {
            name: "revoked writer re-granted",
            spec: "spec/permissions.md §5.2",
            source: "roles-model content::frontier_decides_pre_revoke_edits (re-granted: both stand)",
            steps: vec![w(1, 1), Sync { from: 1, to: 0 }, tick.clone(), revoke.clone(), tick.clone(), w(1, 2), tick.clone(), Edge { by: 0, t: 0, holder: 1, role: Some(Role::Write) }],
            orders: None,
        },
        Scenario {
            name: "snapshot before the revoke carries the unseen edit",
            spec: "spec/permissions.md §5.2",
            source: "roles-model content::snapshots_vouch_for_nothing (snapshot at t=4: the delta stays invalid)",
            steps: vec![w(1, 1), Sync { from: 1, to: 2 }, tick.clone(), Compact { by: 2, t: 0, op: 0 }, tick.clone(), revoke.clone()],
            orders: None,
        },
        Scenario {
            name: "snapshot after the revoke carries the unseen edit",
            spec: "spec/permissions.md §5.2",
            source: "roles-model content::snapshots_vouch_for_nothing (snapshot at t=6)",
            steps: vec![w(1, 1), Sync { from: 1, to: 2 }, tick.clone(), revoke.clone(), tick.clone(), Compact { by: 2, t: 0, op: 0 }],
            orders: None,
        },
        Scenario {
            name: "concurrent cross removals, the earlier wins",
            spec: "spec/permissions.md §5.1",
            source: "roles-model single::mutual_removal_earlier_wins, joint::concurrent_cross_removals",
            steps: vec![Edge { by: 0, t: 0, holder: 1, role: Some(Role::Admin) }, Sync { from: 0, to: 1 }, tick.clone(), Edge { by: 1, t: 0, holder: 2, role: None }, tick.clone(), Edge { by: 2, t: 0, holder: 1, role: None }],
            orders: None,
        },
        Scenario {
            name: "concurrent cross removals, the first admin removes the earlier unseen",
            spec: "spec/permissions.md §5.1",
            source: "roles-model joint::concurrent_cross_removals (the first admin's removal of x drops x's removal of y)",
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
            steps: vec![Nested { by: 2, other: 1, t: 6, k: 0, text: false, compact: true, also: false }, New { by: 2, parent: 1, write: true }, Send { from: 1, to: 0, back: 1 }, Edge { by: 0, t: 2, holder: 2, role: Some(Role::Read) }],
            orders: None,
        },
    ]
}

/// One hand-picked scenario per rule of `until` and invite edges (spec/permissions.md §2).
fn edges() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    vec![
        // spec/permissions.md §2, §5.2: an edge counts as removed from `until` on
        Scenario {
            name: "until passes: the edge ends",
            spec: "spec/permissions.md §2, §5.2",
            source: "hand-picked: 0 sets 1's write edge to end 2.5 s on (1 not told), 1 writes 1 s and 3 s on (the first valid, the second invalid: the edge expired)",
            steps: vec![Grant { by: 0, t: 0, holder: 1, role: Role::Write, until: Some(2500), invite: None, flow: false }, tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 1 }, tick.clone(), tick.clone(), Write { by: 1, t: 0, op: 0, k: 0, v: 2 }],
            orders: None,
        },
        // spec/permissions.md §2: an invite grant adds an edge up to the author's invite (beyond
        // it: `invites()`)
        Scenario {
            name: "invite grant",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-picked: 0 removes 2 and grants 1 write with invite write; 1 grants 2 write by invite (applies); 2 writes (valid)",
            steps: vec![Edge { by: 0, t: 0, holder: 2, role: None }, Grant { by: 0, t: 0, holder: 1, role: Role::Write, until: None, invite: Some(Role::Write), flow: true }, Sync { from: 0, to: 1 }, tick.clone(), Grant { by: 1, t: 0, holder: 2, role: Role::Write, until: None, invite: None, flow: true }, Sync { from: 1, to: 2 }, tick.clone(), Write { by: 2, t: 0, op: 0, k: 0, v: 1 }],
            orders: None,
        },
    ]
}

/// Invite grants the inviter's invite does not cover (spec/permissions.md §2, §5.1): bare edge
/// writes, which the writer's checks refuse, except where the inviter did not know yet. In each,
/// 0 removed 2 and gave 1 write with an invite first.
fn invites() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    let start = |invite: Role| vec![Edge { by: 0, t: 0, holder: 2, role: None }, Grant { by: 0, t: 0, holder: 1, role: Role::Write, until: None, invite: Some(invite), flow: false }, Sync { from: 0, to: 1 }, tick.clone()];
    let then = |base: Vec<Step>, more: Vec<Step>| base.into_iter().chain(more).collect::<Vec<_>>();
    let w2 = HostileWrite { by: 2, t: 0, v: 1 };
    vec![
        Scenario {
            name: "invite grant with a role above the invite",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 1 (invite read) grants 2 write: not applied, 2's write invalid",
            steps: then(start(Role::Read), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), invite: None }, Sync { from: 1, to: 2 }, tick.clone(), w2.clone()]),
            orders: None,
        },
        // §2: an edge value with `invite` above its role is bad by itself, whoever writes it and
        // however it is carried: the delta applies nothing, its resets included
        Scenario {
            name: "edge with an invite above its role, by an invite holder",
            spec: "spec/permissions.md §2, spec/commits.md §4",
            source: "hand-built: 1 (invite read) grants 2 read with invite write: the commit is bad input",
            steps: then(start(Role::Read), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Read), invite: Some(Role::Write) }]),
            orders: None,
        },
        Scenario {
            name: "edge with an invite above its role, by an admin",
            spec: "spec/permissions.md §2, spec/commits.md §4",
            source: "hand-built: 0 rewrites 2's write edge to read with invite write: the commit is bad input, 2's edge stands and 2's later write is valid",
            steps: vec![Edge { by: 0, t: 0, holder: 2, role: Some(Role::Write) }, Sync { from: 0, to: 2 }, tick.clone(), Hostile { by: 0, t: 0, holder: 2, role: Some(Role::Read), invite: Some(Role::Write) }, tick.clone(), w2.clone()],
            orders: None,
        },
        Scenario {
            name: "invite grant within the invite, control",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 1 (invite read) grants 2 read: applied, with no boxes (the edge is judged on its own); 2's write invalid (read)",
            steps: then(start(Role::Read), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Read), invite: None }, Sync { from: 1, to: 2 }, tick.clone(), w2.clone()]),
            orders: None,
        },
        Scenario {
            name: "invite grant over a current edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2 holds read; 1 (invite write) writes 2's edge to write: an invite adds edges only, not applied",
            steps: then(start(Role::Write), vec![Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), invite: None }]),
            orders: None,
        },
        Scenario {
            name: "invite grant over an expired edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2's read edge ended by `until`; 1 (invite write) grants 2 write: an expired edge counts as none, applied",
            steps: then(start(Role::Write), vec![Grant { by: 0, t: 0, holder: 2, role: Role::Read, until: Some(500), invite: None, flow: false }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), invite: None }]),
            orders: None,
        },
        Scenario {
            name: "invite holder removes another edge",
            spec: "spec/permissions.md §2, §5.1",
            source: "hand-built: 2 holds read; 1 (invite write) removes 2's edge: invite holders change no other edge, not applied",
            steps: then(start(Role::Write), vec![Edge { by: 0, t: 0, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Hostile { by: 1, t: 0, holder: 2, role: None, invite: None }]),
            orders: None,
        },
        // §5.1 step 4: an invite level is a class; losing it audits the grants made through it
        Scenario {
            name: "invite grant unseen by the invite's removal",
            spec: "spec/permissions.md §5.1, §7",
            source: "hand-picked: 1 (invite write) grants 2 write, unseen by 0; 0 removes 1 with its frontier: the grant goes to D",
            steps: then(start(Role::Write), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), invite: None }, tick.clone(), Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false }]),
            orders: None,
        },
        Scenario {
            name: "invite grant seen by the invite's removal",
            spec: "spec/permissions.md §5.1, §7",
            source: "hand-picked: 1 (invite write) grants 2 write and 0 receives it; 0 removes 1 with its frontier: the grant stands",
            steps: then(start(Role::Write), vec![Hostile { by: 1, t: 0, holder: 2, role: Some(Role::Write), invite: None }, Sync { from: 1, to: 0 }, tick.clone(), Demote { by: 0, t: 0, holder: 1, at: 9, to_read: false }]),
            orders: None,
        },
        // §2: an over-invite grant's `secrets.0` gets no exemption
        Scenario {
            name: "invite grant through the flow after the invite went",
            spec: "spec/permissions.md §2, §5.1, §5.2",
            source: "hand-picked: 1 holds read with invite read; 0 rewrites it to read without invite, unseen by 1, which grants 2 read through the flow: the edge is not applied and its `secrets.0` delta, no longer exempt, needs write: invalid",
            steps: vec![Edge { by: 0, t: 0, holder: 2, role: None }, Edge { by: 0, t: 0, holder: 1, role: None }, Grant { by: 0, t: 0, holder: 1, role: Role::Read, until: None, invite: Some(Role::Read), flow: true }, Sync { from: 0, to: 1 }, tick.clone(), Grant { by: 0, t: 0, holder: 1, role: Role::Read, until: None, invite: None, flow: false }, tick.clone(), Grant { by: 1, t: 0, holder: 2, role: Role::Read, until: None, invite: None, flow: true }],
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

/// One history over two labels (`bundle`'s `second`): one commit, a part under each. H's first admin
/// is 0, so only H's own edge gives 1 a role on it.
fn labels() -> Vec<Scenario> {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    /// The entries before the last commit (its parts span both labels, `two`) that come after
    /// the setup, and the setup.
    fn entries(played: &Played, of: &[usize]) -> (Vec<usize>, Vec<Tok>, Vec<usize>) {
        let b = played.base;
        let two: Vec<usize> = (0..of.len()).filter(|e| of[*e] == played.packs.len() - 1).collect();
        assert_eq!(two.len(), 2, "a part under each label");
        let k = of.iter().position(|x| *x == b).unwrap();
        ((k..two[0]).collect(), (0..k).map(Tok::In).collect(), two)
    }
    fn orders(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
        let (c, setup, two) = entries(played, of);
        let h = Tok::Sync(played.things[1]);
        let list = |pre: &[Tok], post: &[usize]| setup.iter().copied().chain(pre.iter().copied()).chain(c.iter().chain(post).map(|e| Tok::In(*e))).collect();
        vec![("both labels", list(&[], &two)), ("one label, the other's thing not synced", list(&[], &two[..1])), ("one label, the other's thing synced", list(&[h], &two[..1])), ("both labels, synced", list(&[h], &two))]
    }
    /// The two parts in both orders, H synced or not, and the withheld edge last.
    fn chainless(played: &Played, of: &[usize], _: &BTreeSet<usize>) -> Vec<(&'static str, Vec<Tok>)> {
        let (edge, last) = (played.base + 1, played.packs.len() - 1);
        let rest: Vec<usize> = (0..of.len()).filter(|e| of[*e] != edge && of[*e] != last).collect();
        let two: Vec<usize> = (0..of.len()).filter(|e| of[*e] == last).collect();
        assert_eq!(two.len(), 2, "a part under each label");
        let edges: Vec<usize> = (0..of.len()).filter(|e| of[*e] == edge).collect();
        let h = Tok::Sync(played.things[1]);
        let list = |pre: &[Tok], post: &[usize]| pre.iter().copied().chain(rest.iter().chain(post).map(|e| Tok::In(*e))).collect::<Vec<Tok>>();
        let (gh, hg) = ([two[0], two[1]], [two[1], two[0]]);
        let early = |parts: &[usize]| std::iter::once(h).chain(parts.iter().chain(&rest).map(|e| Tok::In(*e))).collect::<Vec<Tok>>();
        let (gh_e, hg_e): (Vec<usize>, Vec<usize>) = (gh.iter().chain(&edges).copied().collect(), hg.iter().chain(&edges).copied().collect());
        vec![
            ("G first", list(&[], &gh)),
            ("H first", list(&[], &hg)),
            // the parts before the rest: with H synced the commit waits whatever part is here
            ("H synced, G first", early(&gh)),
            ("H synced, H first", early(&hg)),
            ("G first, the edge last", list(&[], &gh_e)),
            ("H first, the edge last", list(&[], &hg_e)),
        ]
    }
    vec![
        Scenario {
            name: "content commit over two labels",
            spec: "spec/commits.md §4, spec/sync.md §3",
            source: "hand-built: 1 writes both G (it holds write) and H (it holds read) in one commit: each delta judged alone; nothing waits for a part",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Two { by: 1, a: 0, b: 1, v: 1 }],
            orders: Some(orders),
        },
        Scenario {
            name: "role commit over two labels",
            spec: "spec/commits.md §4, spec/permissions.md §5.1",
            source: "hand-built: 0 grants 1 read on both G and H in one role commit: a role commit never waits for its other deltas",
            steps: vec![NewTop { by: 0 }, tick.clone(), TwoEdges { by: 0, a: 0, b: 1, holder: 1, role: Role::Read }],
            orders: Some(orders),
        },
        Scenario {
            name: "content commit, its author's chain to H away",
            spec: "spec/commits.md §4, spec/requirements.md Decentralization",
            source: "hand-built: 1 writes both G and H, the edge giving it a path to H withheld: H's part waits alone in either order, H synced or not; the edge arriving ends as in order",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick.clone(), Two { by: 1, a: 0, b: 1, v: 1 }],
            orders: Some(chainless),
        },
        Scenario {
            name: "role commit, its author's chain to H away",
            spec: "spec/commits.md §4, spec/requirements.md Decentralization",
            source: "hand-built: 2 (admin on G) sets 1's edge on G and H, the edge giving it a path to H withheld: G's roster changes in either order, H synced or not",
            steps: vec![NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 2 }, tick.clone(), TwoEdges { by: 2, a: 0, b: 1, holder: 1, role: Role::Read }],
            orders: Some(chainless),
        },
    ]
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
            source: "hand-picked: 1 writes a value above CHUNK_THRESHOLD; the bundle leaves out its chunks, which nothing waits for: the commit applies",
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
/// they do not, and expired puts' value-less records.
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
            source: "order harness, shrunk: two expired map puts: their value-less records",
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
    let mut bundles: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for c in f.live() {
        let name = c.req("case")?;
        let b = c.req("bundle")?;
        let bytes = match b.strip_prefix("as in ") {
            Some(other) => bundles.get(other).cloned().ok_or_else(|| format!("{name}: no case {other}"))?,
            None => [&setup[..], &osis_base::hex::decode(b).ok_or_else(|| format!("{name}: bad bundle hex"))?].concat(),
        };
        bundles.insert(name.to_string(), bytes.clone());
        if only.is_some_and(|x| x != name) {
            continue;
        }
        let mut reads = Vec::new();
        for x in c.req("read-secret")?.split(',') {
            let b = osis_base::hex::decode(x).ok_or("bad read-secret")?;
            reads.push(Secret32::from_bytes(b.try_into().map_err(|_| "read-secret length")?));
        }
        let now = WallMs(c.req("now")?.parse().map_err(|_| "bad now")?);
        let mut got = replay(&bytes, &reads, now, &parse_order(c.req("order")?));
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

// spec/permissions.md §5, spec/commits.md §5: every judgment vector (core/test/vectors/README.md,
// `judgment/`), generated in memory, has its inputs and a bundle that imports, and replayed from
// its text through a fresh engine judges as generated.
#[test]
fn judgment_vectors_spec_permissions_5_2() {
    for (path, text) in files() {
        osis_vectors::subjects::judgment::check(&VecFile::parse(&text).unwrap()).unwrap_or_else(|e| panic!("{path}: {e}"));
        let n = replay_file(path, &text).unwrap_or_else(|e| panic!("{e}"));
        assert!(n > 0, "{path}: no cases");
    }
}

// spec/requirements.md Decentralization, spec/commits.md §4: one held set, its parts in two
// orders: the H part, its chain away, waits alone either way and G's write stands.
#[test]
fn chainless_part_order_spec_commits_4() {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    let played = play(SEED, &[NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 1, role: Some(Role::Read) }, Sync { from: 0, to: 1 }, tick, Two { by: 1, a: 0, b: 1, v: 1 }]);
    let laid = bundle(&played, true);
    let (edge, last) = (played.base + 1, played.packs.len() - 1);
    let rest: Vec<usize> = (0..laid.of.len()).filter(|e| laid.of[*e] != edge && laid.of[*e] != last).collect();
    let two: Vec<usize> = (0..laid.of.len()).filter(|e| laid.of[*e] == last).collect();
    let judge = |parts: &[usize]| replay(&laid.bytes, &read_secrets(true), played.now, &rest.iter().chain(parts).map(|e| Tok::In(*e)).collect::<Vec<_>>());
    assert_eq!(judge(&two), judge(&[two[1], two[0]]));
}

// spec/requirements.md Decentralization, spec/commits.md §4: the same with a role commit: 2 (admin
// on G, a read edge on H not delivered) sets 1's edge on G and H; either order changes G's roster.
#[test]
fn chainless_role_part_order_spec_commits_4() {
    use Step::*;
    let tick = Advance { who: None, ms: 1000 };
    let played = play(SEED, &[NewTop { by: 0 }, tick.clone(), Edge { by: 0, t: 1, holder: 2, role: Some(Role::Read) }, Sync { from: 0, to: 2 }, tick, TwoEdges { by: 2, a: 0, b: 1, holder: 1, role: Role::Read }]);
    let laid = bundle(&played, true);
    let (edge, last) = (played.base + 1, played.packs.len() - 1);
    let rest: Vec<usize> = (0..laid.of.len()).filter(|e| laid.of[*e] != edge && laid.of[*e] != last).collect();
    let two: Vec<usize> = (0..laid.of.len()).filter(|e| laid.of[*e] == last).collect();
    let roster = |parts: &[usize]| {
        let order: Vec<Tok> = rest.iter().chain(parts).map(|e| Tok::In(*e)).collect();
        replay(&laid.bytes, &read_secrets(true), played.now, &order).into_iter().find(|(k, _)| *k == format!("thing {}", played.things[0])).unwrap().1
    };
    assert_eq!(roster(&two), roster(&[two[1], two[0]]));
}

// spec: none (a check of the judgment vectors): in every case, flipping its first own verdict
// makes the replay report that case; in some case of every file, so does dropping the last step
// of its order (a step a user cannot see, such as a commit that waits or is refused, leaves the
// judgment alone).
#[test]
#[ignore]
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
            let e = replay_cases(path, &in_case(&own.0, &flip), Some(name)).expect_err(&format!("{name}: a changed verdict passes"));
            assert!(e.contains(name), "{e}");
            let order = c.req("order").unwrap();
            let shorter = &order[..order.rfind(',').unwrap()];
            if let Err(e) = replay_cases(path, &in_case("order", shorter), Some(name)) {
                assert!(e.contains(name), "{e}");
                shown = true;
            }
        }
        assert!(shown, "{path}: no case's order shows");
    }
}
