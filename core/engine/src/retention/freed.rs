//! Freed sets (spec/sync.md §7 Freed links): a dropped body's links (its values' tree roots and
//! its pages) join a per-thing set, local only, before the body goes. Each link is judged when
//! its delete is sent, against the sources of its thing held then (bodies and live states,
//! `tree_refs`): one a held source reaches leaves the set, kept; one no held source reaches is
//! freed: an interior node's links join the set (a node is immutable, so a linked node's whole
//! subtree stays linked and the walk stops at shared nodes), node-sync drops its bytes here and
//! deletes it at every host holding an entry of it, by the delete keys its link names (Del, the
//! writer's claim: a host checks the delete against the prefix), then it leaves the set
//! (`Engine::freed_done`). A judgment needing a node blob not held waits for it (`wants`).
//!
//! A judged link keeps no key here: what it needs to delete (its blob ID, salt, Del and thing
//! blind) stays, so a dropped body's pieces are unopenable from the store at the end of the
//! drop's transaction (spec/sync.md §7 Freed links), where every freed set that took links is
//! judged (`settle_due`). A link waiting for a node blob keeps its key until it is walked.
//!
//! A held blob is checked against its link first: a prefix that does not bear the link's Del under
//! the thing's blind is no piece of this thing by this link (a link copied from another thing, a
//! false Del), so its bytes stay and it is not walked or deleted (`tree::bears`).
//!
//! Rows: `fl/` + blob ID + tid, in the class of the body that freed them (a memory commit's are
//! memory rows, gone at a restart as the pieces are).

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, BlobId, CommitId, Link, Tid, Value};
use osis_crypto::DeleteSecret;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// One freed link of a thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Freed {
    pub tid: Tid,
    pub link: Link,
    /// The author of the body that freed it (whose chain holds a level-2 delete key it names).
    pub author: Tid,
    /// Its thing blind (spec/crypto.md §7), kept when the key goes.
    blind: [u8; 16],
    /// Known to be a chunk (a level-1 node's child): judged without its bytes.
    leaf: bool,
    /// Judged freed at least once: walked, its bytes gone here, kept out of the store.
    judged: bool,
    /// Its bytes were held when judged and their prefix bears its Del under the thing's blind:
    /// the label delete key may delete it.
    pub borne: bool,
    memory: bool,
}

impl Freed {
    fn new(tid: Tid, link: Link, author: Tid, leaf: bool, memory: bool) -> Freed {
        let blind = osis_crypto::thing_blind(&osis_crypto::link_blind(&link.key), tid.as_bytes());
        Freed { tid, link, author, blind, leaf, judged: false, borne: false, memory }
    }

    /// Whether it is a memory blob's (an ephemeral commit's piece).
    pub fn memory(&self) -> bool {
        self.memory
    }

    /// The blinding a delete by level signs for: the link's salt and its thing blind.
    pub fn blinding(&self) -> ([u8; 16], [u8; 16]) {
        (self.link.salt, self.blind)
    }

    fn key(&self) -> Vec<u8> {
        key(&self.link.blob, &self.tid)
    }

    fn encode(&self) -> Vec<u8> {
        let flags = u8::from(self.leaf) | u8::from(self.judged) << 1 | u8::from(self.borne) << 2 | u8::from(self.memory) << 3;
        Wr::new().u8(flags).raw(self.author.as_bytes()).raw(&self.blind).raw(&osis_base::encode(&Value::Link(Box::new(self.link)))).take()
    }

    fn decode(k: &[u8], v: &[u8]) -> Result<Freed> {
        let mut r = Rd::new(k);
        let _blob: [u8; 32] = r.arr()?;
        let tid = r.tid()?;
        let mut r = Rd::new(v);
        let flags = r.u8()?;
        let author = r.tid()?;
        let blind = r.arr()?;
        let rest = r.rest();
        let Ok(Value::Link(link)) = osis_base::decode(rest, &osis_base::Limits { max_depth: 8, max_bytes: rest.len() }) else { return Err(Error::Corrupt("freed link")) };
        Ok(Freed { tid, link: *link, author, blind, leaf: flags & 1 != 0, judged: flags & 2 != 0, borne: flags & 4 != 0, memory: flags & 8 != 0 })
    }
}

fn key(b: &BlobId, t: &Tid) -> Vec<u8> {
    [records::FREED, &b.0, t.as_bytes()].concat()
}

/// A row a link's blob key may have been committed in (one waiting for a node blob) is
/// overwritten and removed shredded (spec/commits.md §5: a dropped body's keys go).
fn put(tx: &mut Tx<'_>, f: &Freed) -> Result<()> {
    tx.in_class(f.memory, |tx| Ok(tx.txn.put_local(&f.key(), &f.encode(), Shred::Yes)?))
}

fn remove(tx: &mut Tx<'_>, f: &Freed) -> Result<()> {
    tx.txn.remove_local(&f.key(), Shred::Yes)?;
    Ok(())
}

fn rows(tx: &mut Tx<'_>, prefix: &[u8]) -> Result<Vec<Freed>> {
    let mut out = Vec::new();
    tx.scan(prefix, |k, v| {
        out.push(Freed::decode(&[prefix.get(records::FREED.len()..).unwrap_or_default(), k].concat(), &v)?);
        Ok(())
    })?;
    Ok(out)
}

/// The links part `ai` of held commit `c` holds: its delta's tree roots and pages, or, held as its
/// leftover, the leftover's values' roots.
pub(crate) fn part_links(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Vec<Link>> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    if m.stripped(ai) {
        let Some(a) = m.header.aspects.get(ai) else { return Ok(out) };
        if let Some(l) = super::leftover::get(tx, &a.tid, &a.ak, c, ai)? {
            l.fragment.values(&mut |v| crate::engine::large::links_in(v, &mut out));
        }
    } else if let Some(blob) = tx.get_commit(c)?
        && let Some(p) = blob.part(ai)
    {
        out = crate::engine::large::delta_roots(&p.delta);
    }
    out.sort_unstable_by_key(|l| l.blob);
    out.dedup_by_key(|l| l.blob);
    Ok(out)
}

/// Part `ai` of `c` drops (or its delta goes, held on as its leftover): the links it holds join
/// its thing's freed set first, to be judged at the transaction's end. A link already in the set
/// stays as it is, judged again then too (the source dropping may be what it waited for).
pub(crate) fn free_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (tid, author, memory) = (a.tid, m.header.actor, m.view.memory);
    for link in part_links(tx, c, ai)? {
        let blob = link.blob;
        add(tx, Freed::new(tid, link, author, false, memory))?;
        tx.core.freed_due.insert((tid, blob));
    }
    Ok(())
}

/// Adds `f` unless its piece is in the set already. Whether it was added.
fn add(tx: &mut Tx<'_>, f: Freed) -> Result<bool> {
    if tx.txn.get_local(&f.key())?.is_some() {
        return Ok(false);
    }
    put(tx, &f)?;
    Ok(true)
}

/// What a judgment of some freed rows found (`Engine::judge_freed`).
#[derive(Clone, Debug, Default)]
pub struct Judgment {
    /// Freed: to delete wherever an entry of it is.
    pub freed: Vec<Freed>,
    /// Those of `freed` judged freed for the first time (walked, their keys gone) or judged again
    /// as their wait ended: their bytes go here and their entries are judged again (a row judged
    /// outside its label's pass is deleted by that label's next pass).
    pub fresh: BTreeSet<BlobId>,
}

/// The rows added this transaction, and the waiting rows of their things (a source dropped may
/// be what they waited for), judged at its end: a judged one keeps no key. What it freed is
/// handed to node-sync (`Core::freed_new`), waiting rows judged freed again included: no pass
/// may have them in scope.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut due = std::mem::take(&mut tx.core.freed_due);
    let things: BTreeSet<Tid> = due.iter().map(|x| x.0).collect();
    due.extend(tx.core.freed_waits.values().flatten().filter(|(t, _)| things.contains(t)));
    let mut fs = Vec::new();
    for (t, b) in due {
        fs.extend(rows(tx, &key(&b, &t))?);
    }
    let j = judge(tx, fs)?;
    tx.core.freed_new.extend(j.freed.iter().map(|f| f.link.blob));
    Ok(())
}

/// Judges freed rows `fs` (the module doc): those a held source of their thing reaches leave
/// the set; the rest are freed, a node's links joining the set and judged in turn; one needing a
/// node blob not held waits for it (`Core::freed_waits`). Costs the rows given and the walk of
/// the nodes they free, plus a memo hit per source of each thing.
fn judge(tx: &mut Tx<'_>, fs: Vec<Freed>) -> Result<Judgment> {
    // counted: tests read how much a deletion judges in all
    crate::costs::count("freed: rows judged", fs.len() as u64);
    let mut by_thing: BTreeMap<Tid, Vec<Freed>> = BTreeMap::new();
    for f in fs {
        by_thing.entry(f.tid).or_default().push(f);
    }
    let mut out = Judgment::default();
    for (t, mut fs) in by_thing {
        let dedup = tx.core.dedup(&t);
        loop {
            let blobs: BTreeSet<BlobId> = fs.iter().map(|f| f.link.blob).collect();
            let refs = crate::engine::tree_refs::tree_refs_in(tx, &t, &blobs)?;
            // what a held source links below a node not held is unknown: every link waits
            if !refs.missing.is_empty() {
                for m in refs.missing {
                    tx.core.freed_waits.entry(m).or_default().extend(blobs.iter().map(|b| (t, *b)));
                }
                break;
            }
            let mut kids = Vec::new();
            for mut f in std::mem::take(&mut fs) {
                if refs.blobs.contains(&f.link.blob) {
                    remove(tx, &f)?;
                    continue;
                }
                if !f.judged {
                    match tx.blobs.get(&f.link.blob)? {
                        Some(bytes) => {
                            let blind = f.blinding().1;
                            if !osis_label::Prefix::parse(&bytes).is_ok_and(|p| osis_label::tree::bears(&p, &f.link.del, &blind)) {
                                remove(tx, &f)?;
                                continue;
                            }
                            if !f.leaf
                                && let Some((leaf, links)) = crate::engine::large::kids_of(dedup.as_ref(), &f.link, &bytes)
                            {
                                kids.extend(links.into_iter().map(|link| Freed::new(t, link, f.author, leaf, f.memory)));
                            }
                            f.borne = true;
                        }
                        None if f.leaf => {}
                        None => {
                            tx.core.freed_waits.entry(f.link.blob).or_default().insert((t, f.link.blob));
                            continue;
                        }
                    }
                    f.judged = true;
                    f.link.key = [0; 32];
                    put(tx, &f)?;
                    out.fresh.insert(f.link.blob);
                }
                out.freed.push(f);
            }
            for k in kids {
                if add(tx, k.clone())? {
                    fs.push(k);
                }
            }
            if fs.is_empty() {
                break;
            }
        }
    }
    Ok(out)
}

/// The rows of `blobs`, and those waiting for a node blob held now (judged again as it came),
/// judged (`judge`). The waits it woke.
fn judge_blobs(tx: &mut Tx<'_>, blobs: &BTreeSet<BlobId>) -> Result<(Judgment, Vec<BlobId>)> {
    let mut fs = Vec::new();
    let mut seen = BTreeSet::new();
    for b in blobs {
        for f in rows(tx, &[records::FREED, &b.0].concat())? {
            seen.insert((f.tid, f.link.blob));
            fs.push(f);
        }
    }
    let waits: Vec<BlobId> = tx.core.freed_waits.keys().copied().collect();
    let (mut woke, mut woken) = (Vec::new(), BTreeSet::new());
    for w in waits {
        if !tx.blobs.held(&w)? {
            continue;
        }
        woke.push(w);
        for (t, b) in tx.core.freed_waits.get(&w).cloned().unwrap_or_default() {
            if seen.insert((t, b)) {
                woken.insert(b);
                fs.extend(rows(tx, &key(&b, &t))?);
            }
        }
    }
    let mut j = judge(tx, fs)?;
    // a woken row may be another label's: its entries are judged again (`Judgment::fresh`)
    let again: Vec<BlobId> = j.freed.iter().map(|f| f.link.blob).filter(|b| woken.contains(b)).collect();
    j.fresh.extend(again);
    Ok((j, woke))
}

/// The forgotten parts of things this node lost read access to (`retention::forget`): their
/// freed sets go (a party removed cannot delete), and of the pieces `roots` reach through held
/// node blobs, those no remaining source of their thing reaches and whose prefix bears their
/// link are this node's to drop. The blobs to release.
/// `aspects`, `parts`: those forgotten, sources no more though still indexed meanwhile.
pub(crate) fn lost(tx: &mut Tx<'_>, things: &BTreeSet<Tid>, roots: BTreeMap<Tid, Vec<Link>>, aspects: &BTreeSet<(Tid, Ak)>, parts: &BTreeMap<CommitId, BTreeSet<usize>>) -> Result<BTreeSet<BlobId>> {
    // rare (a role change): a scan of every row, keeping those of `things` alone
    tx.remove_scanned(records::FREED, |k| {
        let mut r = Rd::new(k);
        let _blob: [u8; 32] = r.arr()?;
        Ok(things.contains(&r.tid()?))
    })?;
    // their waits go too: nothing is fetched for a thing lost
    tx.core.freed_waits.retain(|_, s| {
        s.retain(|(t, _)| !things.contains(t));
        !s.is_empty()
    });
    let mut out = BTreeSet::new();
    for (t, mut todo) in roots {
        let dedup = tx.core.dedup(&t);
        let mut seen = BTreeSet::new();
        while !todo.is_empty() {
            todo.retain(|l| seen.insert(l.blob));
            let blobs: BTreeSet<BlobId> = todo.iter().map(|l| l.blob).collect();
            let refs = kept_refs(tx, &t, &blobs, aspects, parts)?;
            let mut next = Vec::new();
            for l in std::mem::take(&mut todo) {
                if refs.blobs.contains(&l.blob) || !refs.missing.is_empty() {
                    continue;
                }
                let Some(bytes) = tx.blobs.get(&l.blob)? else { continue };
                let blind = osis_crypto::thing_blind(&osis_crypto::link_blind(&l.key), t.as_bytes());
                if !osis_label::Prefix::parse(&bytes).is_ok_and(|p| osis_label::tree::bears(&p, &l.del, &blind)) {
                    continue;
                }
                if let Some((_, kids)) = crate::engine::large::kids_of(dedup.as_ref(), &l, &bytes) {
                    next.extend(kids);
                }
                out.insert(l.blob);
            }
            todo = next;
        }
    }
    Ok(out)
}

/// What the sources of `t` a lost-access forget keeps link among `blobs` (`tree_refs`): every
/// source but the forgotten `aspects`' states and the bodies all of whose held parts on `t` are
/// among the forgotten `parts` (still indexed while the forget runs).
pub(crate) fn kept_refs(tx: &mut Tx<'_>, t: &Tid, blobs: &BTreeSet<BlobId>, aspects: &BTreeSet<(Tid, Ak)>, parts: &BTreeMap<CommitId, BTreeSet<usize>>) -> Result<crate::engine::large::Trees> {
    use crate::engine::tree_refs::{Source, kept_refs_in, sources_of};
    let t = *t;
    let srcs = sources_of(tx, &t)?;
    let core = &*tx.core;
    let body_gone = |c: &CommitId| core.ix.commits.get(c).is_none_or(|m| m.view.aspects_on(&t).filter(|ai| m.holds(*ai)).all(|ai| parts.get(c).is_some_and(|w| w.contains(&ai))));
    let skip: BTreeSet<Source> = srcs
        .into_iter()
        .filter(|s| match s {
            Source::State(ak) => aspects.contains(&(t, ak.clone())),
            Source::Body(c) => body_gone(c),
        })
        .collect();
    kept_refs_in(tx, &t, blobs, &|s| skip.contains(s))
}

impl Engine {
    /// Judges the freed rows of `blobs` now, and those waiting for a node blob held now
    /// (`retention::freed`): what to delete, and which of it to release here.
    pub fn judge_freed(&mut self, blobs: &BTreeSet<BlobId>) -> Result<Judgment> {
        let (j, woke) = self.run(|tx| judge_blobs(tx, blobs))?;
        for w in woke {
            self.core.freed_waits.remove(&w);
        }
        Ok(j)
    }

    /// Judges a page of every freed row (a start, a judgment of everything), from row key
    /// `from` on (empty: the first): its judgment, and where the next page starts (`None`: none
    /// left). Memory per page, whatever the set's size.
    pub fn judge_freed_page(&mut self, from: &[u8]) -> Result<(Judgment, Option<Vec<u8>>)> {
        let page = crate::engine::SCAN_PAGE;
        self.run(|tx| {
            let got = tx.txn.scan_local(records::FREED, from, page)?;
            let next = (got.len() == page).then(|| got.last().map(|(k, _)| [k.get(records::FREED.len()..).unwrap_or_default(), &[0]].concat())).flatten();
            let mut fs = Vec::new();
            for (k, v) in got {
                fs.push(Freed::decode(k.get(records::FREED.len()..).unwrap_or_default(), &v)?);
            }
            Ok((judge(tx, fs)?, next))
        })
    }

    /// The blobs judged freed since the last call (`Core::freed_new`): node-sync releases them
    /// and judges their entries again.
    pub fn take_freed_new(&mut self) -> BTreeSet<BlobId> {
        std::mem::take(&mut self.core.freed_new)
    }

    /// The node blobs freed-set judgments wait for (`Core::freed_waits`): to fetch.
    pub fn freed_wants(&self) -> impl Iterator<Item = &BlobId> + '_ {
        self.core.freed_waits.keys()
    }

    /// Freed links gone from every label entry known here: they leave the set.
    pub fn freed_done(&mut self, done: &[(Tid, BlobId)]) -> Result<()> {
        if done.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            for (t, b) in done {
                tx.txn.remove_local(&key(b, t), Shred::Yes)?;
            }
            Ok(())
        })
    }

    /// Whether blob `b` was judged freed here: its bytes are not kept, whoever brings them.
    pub fn is_freed(&mut self, b: &BlobId) -> Result<bool> {
        let prefix = [records::FREED, &b.0].concat();
        self.read(|tx| Ok(rows(tx, &prefix)?.iter().any(|f| f.judged)))
    }

    /// Every freed link held.
    #[cfg(test)]
    pub(crate) fn freed_links(&mut self) -> Result<Vec<Freed>> {
        self.read(|tx| rows(tx, records::FREED))
    }

    /// The delete secrets this node holds for the keys freed link `f` names (spec/crypto.md §7:
    /// levels 1 and 3 along its thing's chain, level 2 along its author's), with their levels.
    pub fn freed_delete_secrets(&self, f: &Freed) -> Vec<(u8, DeleteSecret)> {
        let thing = self.core.delete_chain(&f.tid);
        let author = self.core.delete_chain(&f.author);
        f.link.del.iter().filter_map(|(level, k)| crate::engine::Core::delete_secret(level, &k, &thing, &author).map(|d| (level, d))).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::Ak;

    /// A peer holding thing `t`'s 1 MiB value written by three own replaces, each an edit
    /// reusing most of the last tree, so the first is covered by the two after it (droppable).
    fn three_replaces() -> (LocalPeer, Tid, Ak, Vec<CommitId>) {
        replaces_of(1 << 20)
    }

    /// `three_replaces` of a value of `n` bytes.
    fn replaces_of(n: usize) -> (LocalPeer, Tid, Ak, Vec<CommitId>) {
        let mut lp = LocalPeer::fresh(1, osis_base::WallMs(1_700_000_000_000));
        let me = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let a = Ak::new("x:b.0").unwrap();
        let mut x = vec![0u8; n];
        osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(1), &mut x);
        let mut cs = Vec::new();
        for i in 0..3 {
            lp.advance(1000);
            x.splice(1000 * (i + 1)..1000 * (i + 1), [i as u8; 50]);
            let mut m = Mutation::new();
            m.set(t, &a, &Value::Bytes(x.clone())).unwrap();
            cs.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
        (lp, t, a, cs)
    }

    /// Judges every freed row (`Engine::judge_freed` of every blob in the set).
    fn judge_all(e: &mut Engine) -> Judgment {
        let all: BTreeSet<BlobId> = e.freed_links().unwrap().iter().map(|f| f.link.blob).collect();
        e.judge_freed(&all).unwrap()
    }

    /// The blobs part 0 of `c` reaches (its value's tree).
    fn tree(e: &mut Engine, t: &Tid, c: &CommitId) -> BTreeSet<BlobId> {
        let t = *t;
        e.run(|tx| {
            let roots = part_links(tx, c, 0)?;
            let dedup = tx.core.dedup(&t).unwrap();
            let mut out = crate::engine::large::Trees::default();
            crate::engine::large::tree_blobs(tx, &dedup, &roots, &mut out)?;
            assert!(out.missing.is_empty());
            Ok(out.blobs)
        })
        .unwrap()
    }

    // spec/sync.md §7 Freed links: a dropped body's pieces no held source of its thing links
    // are freed (the walk follows its unshared nodes and stops at shared ones); none a held
    // body or the live state links is; and each is judged by the delete keys of its link.
    #[test]
    fn dropped_body_frees_exactly_its_unlinked_pieces_spec_sync_7() {
        let (mut lp, t, a, cs) = three_replaces();
        let e = &mut lp.peers[0].engine;
        let trees: Vec<BTreeSet<BlobId>> = cs.iter().map(|c| tree(e, &t, c)).collect();
        e.drop_body(&cs[0], &t, &a).unwrap();
        let j = judge_all(e);
        let want: BTreeSet<BlobId> = trees[0].iter().filter(|b| !trees[1].contains(b) && !trees[2].contains(b)).copied().collect();
        assert!(!want.is_empty() && want.len() < trees[0].len(), "an edit leaves some pieces, shares the rest");
        assert_eq!(j.freed.iter().map(|f| f.link.blob).collect::<BTreeSet<_>>(), want, "freed: the dropped body's pieces nothing held links");
        // judged in the drop's transaction: no key of a freed piece stays (spec/commits.md §5)
        assert!(e.freed_links().unwrap().iter().all(|f| f.judged && f.link.key == [0; 32]), "freed links keep no key");
        assert_eq!(e.freed_wants().count(), 0);
        assert_eq!(e.take_freed_new(), want, "handed to node-sync as judged");
        assert!(j.freed.iter().all(|f| f.borne && f.tid == t && !f.link.del.is_empty()), "held, borne, deletable by its keys");
        assert!(j.freed.iter().all(|f| e.freed_delete_secrets(f).len() == f.link.del.len()), "the writer holds every key its links name");
        // judged again: the same set
        assert_eq!(judge_all(e).freed.len(), want.len());
        for b in &want {
            assert!(e.is_freed(b).unwrap());
        }
        let done: Vec<(Tid, BlobId)> = want.iter().map(|b| (t, *b)).collect();
        e.freed_done(&done).unwrap();
        assert!(e.freed_links().unwrap().is_empty());
        // a snapshot is a source by its links too (its frontiers are no values)
        let s1 = e.snapshot(&t, &a).unwrap().unwrap();
        assert_eq!(e.run(|tx| part_links(tx, &s1, 0)).unwrap().len(), 1, "a snapshot links its value's root");
    }

    // spec/sync.md §7 Freed links (a judgment needs every node blob of the held sources'
    // trees): a held body's tree node not held blocks its thing's judgments, which ask for it;
    // once it is held, the next judgment of anything judges them.
    #[test]
    fn a_held_sources_missing_node_waits_spec_sync_7() {
        let (mut lp, t, a, cs) = three_replaces();
        let e = &mut lp.peers[0].engine;
        let root = e.run(|tx| part_links(tx, &cs[1], 0)).unwrap()[0];
        let bytes = e.blob(&root.blob).unwrap().unwrap();
        e.run(|tx| tx.blobs.release(&root.blob, false)).unwrap();
        e.drop_body(&cs[0], &t, &a).unwrap();
        let j = judge_all(e);
        assert!(j.freed.is_empty(), "nothing judged while a held tree is unknown");
        assert!(e.freed_wants().any(|b| *b == root.blob), "the node is asked for");
        assert!(e.freed_links().unwrap().iter().all(|f| !f.judged && f.link.key != [0; 32]), "a waiting link keeps its key");
        e.put_blobs(vec![(root.blob, bytes)]).unwrap();
        let j = e.judge_freed(&BTreeSet::new()).unwrap();
        assert!(!j.freed.is_empty() && j.fresh.len() == j.freed.len(), "judged once the node came");
        assert_eq!(e.freed_wants().count(), 0);
    }

    // spec/sync.md §7 Freed links: a link judged freed whose next judgment waits for a held
    // source's node (a co-writer's new tree not fetched yet) is handed on again once the node
    // comes, as one judged anew: its entries are judged again under their own label, whichever
    // pass woke it, so its delete at hosts is not stranded.
    #[test]
    fn a_judged_link_woken_from_a_wait_is_handed_on_spec_sync_7() {
        let (mut lp, t, a, cs) = three_replaces();
        let e = &mut lp.peers[0].engine;
        e.drop_body(&cs[0], &t, &a).unwrap();
        let freed = e.take_freed_new();
        assert!(!freed.is_empty());
        let root = e.run(|tx| part_links(tx, &cs[1], 0)).unwrap()[0];
        let bytes = e.blob(&root.blob).unwrap().unwrap();
        e.run(|tx| tx.blobs.release(&root.blob, false)).unwrap();
        // a held source's node released (only a test does so): its counted trees are read anew
        e.core.tree_reach.clear();
        assert!(judge_all(e).freed.is_empty(), "judged links wait while a held tree is unknown");
        e.put_blobs(vec![(root.blob, bytes)]).unwrap();
        let j = e.judge_freed(&BTreeSet::new()).unwrap();
        let got: BTreeSet<BlobId> = j.freed.iter().map(|f| f.link.blob).collect();
        assert_eq!(got, freed, "judged again once the node came");
        assert_eq!(j.fresh, freed, "handed on so their labels judge them again");
    }

    // spec/crypto.md §7, spec/sync.md §7 Freed links (a link is judged under its own thing; a
    // held blob whose prefix does not bear the link under that thing is no piece of it): a
    // writer of t1 who reads t2 sets a t1 value to t2's value link verbatim. Its body dropped,
    // nothing of t2 is freed, released or deleted, and t1's link kept nothing of t2 alive.
    #[test]
    fn a_link_copied_from_another_thing_frees_nothing_spec_crypto_7() {
        let (mut lp, t2, a, _) = three_replaces();
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let t1 = e.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let e = &mut lp.peers[0].engine;
        let Some(Value::Link(l)) = e.get(&t2, &a).unwrap() else { panic!("t2 holds a large value") };
        let live = e.live_trees(&t2).unwrap().blobs;
        let mut cs = Vec::new();
        for v in [Value::Link(l.clone()), Value::Int(1), Value::Int(2)] {
            lp.advance(1000);
            let mut m = Mutation::new();
            m.set(t1, &a, &v).unwrap();
            cs.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.run(|tx| part_links(tx, &cs[0], 0)).unwrap(), vec![*l], "t1's body links t2's root");
        e.drop_body(&cs[0], &t1, &a).unwrap();
        let j = judge_all(e);
        assert!(j.freed.is_empty(), "nothing of t2 freed under t1");
        assert!(e.freed_links().unwrap().is_empty(), "the link leaves the set");
        assert!(live.iter().all(|b| e.has_blob(b)), "t2's tree held");
    }

    // spec/sync.md §7 Freed links (the walk stops at shared nodes), notes/coordination.md (check
    // scaling): dropping an edited version of a value frees what the edit replaced, flat in the
    // value's size; the freed set holds no more.
    #[test]
    fn an_edits_drop_frees_flat_in_value_size_spec_sync_7() {
        let freed = |n: usize| {
            let (mut lp, t, a, cs) = replaces_of(n);
            let e = &mut lp.peers[0].engine;
            e.drop_body(&cs[0], &t, &a).unwrap();
            e.freed_links().unwrap().len()
        };
        let (small, big) = (freed(256 << 10), freed(2560 << 10));
        assert!(small > 0, "an edit frees some pieces");
        assert!(big <= small + 4, "freed links of an edit: {small} at n, {big} at 10n");
    }

    /// Peer 0 writes thing `t1` (and `t2`) and grants peer 1 read on both; `t2` holds a 1 MiB
    /// value, and `t1` holds `t1_value(t2's link)`. Then peer 1 is removed from `t1` and drops
    /// what it lost. How many blobs of `t1`'s tree peer 1 still holds, and whether it holds all
    /// of `t2`'s.
    fn lose_t1(t1_value: impl Fn(&Link) -> Value) -> (usize, bool) {
        use crate::flows::Demotion;
        use osis_base::Role;
        use osis_schema::core_types::Edge;
        let mut lp = LocalPeer::fresh(2, osis_base::WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (me, v) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let mut m = Mutation::new();
        let t1 = lp.peers[0].engine.new_thing(&mut m, me);
        let t2 = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let read = Edge { role: Role::Read, until: None, invite: None, tied: None };
        for t in [t1, t2] {
            lp.peers[0].engine.grant(&t, &v, &read).unwrap();
        }
        lp.sync_all().unwrap();
        let a = Ak::new("x:b.0").unwrap();
        let mut x = vec![0u8; 1 << 20];
        osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(1), &mut x);
        let mut m = Mutation::new();
        m.set(t2, &a, &Value::Bytes(x.clone())).unwrap();
        lp.peers[0].commit(m).unwrap();
        let Some(Value::Link(l2)) = lp.peers[0].engine.get(&t2, &a).unwrap() else { panic!("t2 holds a large value") };
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t1, &a, &t1_value(&l2)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        let tree1 = lp.peers[0].engine.live_trees(&t1).unwrap().blobs;
        let tree2 = lp.peers[0].engine.live_trees(&t2).unwrap().blobs;
        assert!(tree1.iter().chain(&tree2).all(|b| lp.peers[1].engine.has_blob(b)), "peer 1 holds both trees");
        lp.advance(1000);
        let removal = lp.peers[0].engine.demote(&t1, &Demotion { holder: v, new: None, retain: None }).unwrap().commits;
        for c in removal {
            let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        e.drop_lost_due().unwrap();
        assert_eq!(e.get(&t1, &a).unwrap(), None, "peer 1 forgot t1");
        assert_eq!(e.get_full(&t2, &a).unwrap(), Some(Value::Bytes(x)), "peer 1 reads t2");
        (tree1.iter().filter(|b| e.has_blob(b)).count(), tree2.iter().all(|b| e.has_blob(b)))
    }

    // spec/permissions.md §3, spec/sync.md §7 Freed links (lost access drops the pieces the
    // forgotten parts reach that no remaining source links), with no node-sync: a reader removed
    // from t1 drops t1's own tree
    #[test]
    fn lost_access_drops_the_things_tree_spec_permissions_3() {
        let mut y = vec![0u8; 1 << 20];
        osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(2), &mut y);
        let (t1, t2) = lose_t1(|_| Value::Bytes(y.clone()));
        assert_eq!(t1, 0, "t1's tree dropped");
        assert!(t2, "t2's tree kept");
    }

    // spec/sync.md §7 Freed links (a piece goes only by a link its prefix bears), spec/crypto.md
    // §7, with no node-sync: t1's value is t2's link copied verbatim; a reader removed from t1
    // drops nothing of t2, though no source of t1 links it any more
    #[test]
    fn lost_access_keeps_another_things_piece_it_linked_spec_crypto_7() {
        let (_, t2) = lose_t1(|l| Value::Link(Box::new(*l)));
        assert!(t2, "t2's tree kept whole");
    }
}
