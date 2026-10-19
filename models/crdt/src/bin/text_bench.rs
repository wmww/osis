//! notes/crdt.md, Text size: replay the automerge-paper trace as one writer and measure the encoded text snapshot.
//! Usage: text-bench <edits.txt> <final.txt>
use crdt_model::stamp::{Dot, Source, Stamp};
use crdt_model::state::{Anchor, Composite, Content, Frag, SeqElem};
use crdt_model::wire::{encode, Ctx};
use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let edits = std::fs::read_to_string(&args[1]).unwrap();
    let final_text = std::fs::read_to_string(&args[2]).unwrap();
    for batch in [1usize, 10, 100] {
        let (state, n_edits) = replay(&edits, batch);
        let got = state.read().unwrap();
        let ok = matches!(&got, crdt_model::value::Value::Str(s) if *s == final_text);
        let Frag::Seq { elems, .. } = &state else { unreachable!() };
        let deleted = elems.values().filter(|e| e.deleted.is_some()).count();
        // snapshot by a compactor (other node, later ts): every stamp in full form
        let mut cx = Ctx::new(u64::MAX / 2, Source::node(9), 1);
        let bytes = crdt_model::wire::encode_delta(&state, [0; 16], &mut cx);
        let it = encode(&state, &cx);
        let frag_bytes = crdt_model::cbor::encode(&it).len();
        let sources_bytes = crdt_model::cbor::encode(&cx.sources_item()).len();
        let flagw: usize = match &it {
            crdt_model::cbor::Item::Array(a) => match &a[3] {
                crdt_model::cbor::Item::Array(r) => r.iter().map(|run| match run { crdt_model::cbor::Item::Array(x) => x[5].array().unwrap().len(), _ => 0 }).sum(),
                _ => 0,
            },
            _ => 0,
        };
        let flag_bytes: usize = match &it {
            crdt_model::cbor::Item::Array(a) => match &a[3] {
                crdt_model::cbor::Item::Array(r) => r.iter().map(|run| match run { crdt_model::cbor::Item::Array(x) => crdt_model::cbor::encode(&x[5]).len(), _ => 0 }).sum(),
                _ => 0,
            },
            _ => 0,
        };
        println!("  commits={} commit_table={}B fragment={}B flag_writes={flagw} flag_bytes={flag_bytes}", cx.commits.len(), bytes.len() - frag_bytes - sources_bytes - 18, frag_bytes);
        let runs = match &it {
            crdt_model::cbor::Item::Array(a) => match &a[3] {
                crdt_model::cbor::Item::Array(r) => r.len(),
                _ => 0,
            },
            _ => 0,
        };
        println!(
            "batch={batch}: edits={n_edits} elements={} deleted={} runs={runs} text={}B snapshot={}B ratio={:.2} final_matches={ok}",
            elems.len(),
            deleted,
            final_text.len(),
            bytes.len(),
            bytes.len() as f64 / final_text.len() as f64
        );
    }
}

/// Replays with `batch` edits per commit (counter continues across commits as a node-form dot does).
/// A commit carries its net effect (spec §4.5): elements inserted and deleted within one commit are omitted, and
/// all deletions of one commit share one flag write (one stamp).
fn replay(edits: &str, batch: usize) -> (Frag, usize) {
    let src = Source::node(1);
    let mut elems: BTreeMap<Dot, SeqElem> = BTreeMap::new();
    let mut created_in: BTreeMap<Dot, u64> = BTreeMap::new();
    let mut children: BTreeMap<Dot, Vec<Dot>> = BTreeMap::new();
    let mut vis: Vec<Dot> = Vec::new();
    let mut ctr = 1u64;
    let mut n = 0usize;
    let mut del_stamp: Option<(u64, Stamp)> = None; // (commit, stamp)
    let mut cur_commit = 0u64;
    let mut lo_of: BTreeMap<u64, u64> = BTreeMap::new();
    // created and deleted in the current commit, omitted at its end once nothing anchors at them
    let mut pending: Vec<Dot> = Vec::new();
    for (k, line) in edits.lines().enumerate() {
        let commit = (k / batch) as u64 + 1;
        // realistic wall clock: 2 s per commit, ms resolution shifted by 16 bits of logical counter
        let ts = (1_760_000_000_000u64 + commit * 2000) << 16;
        if commit != cur_commit {
            cur_commit = commit;
            lo_of.insert(commit, ctr); // commit-level writes share counter lo; the first creation also uses it
        }
        let mut it = line.split('\t');
        let pos: usize = it.next().unwrap().parse().unwrap();
        let del: usize = it.next().unwrap().parse().unwrap();
        let ins: String = serde_lite(it.next().unwrap());
        if del > 0 {
            let s = match &del_stamp {
                Some((c, s)) if *c == commit => s.clone(),
                _ => {
                    // commit-level write: the delta dot, consumed at the start of the commit
                    let s = Stamp::new(ts, src.clone(), delta_lo(ctr, commit, &mut lo_of));
                    del_stamp = Some((commit, s.clone()));
                    s
                }
            };
            for d in vis.drain(pos..pos + del) {
                elems.get_mut(&d).unwrap().deleted = Some((s.clone(), true));
                if created_in[&d] == commit {
                    pending.push(d);
                }
            }
        }
        let mut anchor = if pos == 0 { Anchor::Head } else { Anchor::Dot(vis[pos - 1].clone()) };
        for (i, ch) in ins.chars().enumerate() {
            let s = Stamp::new(ts, src.clone(), ctr);
            ctr += 1;
            let d = s.dot.clone();
            if let Anchor::Dot(p) = &anchor {
                children.entry(p.clone()).or_default().push(d.clone());
            }
            elems.insert(d.clone(), SeqElem::new(s, anchor, Content::Char(ch)));
            created_in.insert(d.clone(), commit);
            vis.insert(pos + i, d.clone());
            anchor = Anchor::Dot(d);
        }
        n += 1;
        if k % batch == batch - 1 {
            omit(&mut pending, &mut elems, &children);
            ctr = ctr.max(lo_of[&commit] + 1);
        }
    }
    omit(&mut pending, &mut elems, &children);
    let f = Frag::Seq { text: true, c: Composite::default(), elems };
    (f, n)
}

/// Spec §4.5: an element created and removed in the commit is omitted once nothing anchors at it,
/// repeatedly (no moves in the trace, so creation anchors are all).
fn omit(pending: &mut Vec<Dot>, elems: &mut BTreeMap<Dot, SeqElem>, children: &BTreeMap<Dot, Vec<Dot>>) {
    loop {
        let before = pending.len();
        pending.retain(|d| {
            let named = children.get(d).is_some_and(|cs| cs.iter().any(|c| elems.contains_key(c)));
            if !named {
                elems.remove(d);
            }
            named
        });
        if pending.len() == before {
            break;
        }
    }
    pending.clear();
}

fn delta_lo(_ctr: u64, commit: u64, lo_of: &mut BTreeMap<u64, u64>) -> u64 {
    lo_of[&commit]
}

/// Minimal JSON string unescape for the trace file (only `\"`, `\\`, `\n`, `\t`, `\uXXXX` occur).
fn serde_lite(s: &str) -> String {
    let inner = &s[1..s.len() - 1];
    let mut out = String::new();
    let mut cs = inner.chars();
    while let Some(c) = cs.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match cs.next().unwrap() {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'u' => {
                let h: String = (0..4).map(|_| cs.next().unwrap()).collect();
                out.push(char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap());
            }
            x => out.push(x),
        }
    }
    out
}
