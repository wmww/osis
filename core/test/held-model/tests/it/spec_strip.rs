//! The per-part strip (notes/whole-commits.md, Strip): the protocol at quiescence against what
//! the history alone says each store holds. spec: spec/sync-judgement.md §2 (per blob).
use held_model::gen::Rng;
use held_model::strip::*;

fn sweep(off: Off, runs: u64) -> Vec<(u64, Diff)> {
    let mut out = Vec::new();
    for seed in 0..runs {
        let mut r = Rng::new(seed);
        let n = 2 + r.below(3) as usize;
        let parts = 1 + r.below(4) as usize;
        let w = world(&mut r, n, parts);
        let h = history(&mut r, &w, 30);
        if let Err(d) = run(&w, &h, off) {
            out.push((seed, d));
        }
    }
    out
}

/// Random histories reach the oracle's stores: no live part lost at K, nothing missing at any
/// reader (new readers of a cover-stripped commit included), one blob per own log, no gone or
/// covered part left where a node could delete it.
#[test]
fn random_histories_reach_the_oracle() {
    let f = sweep(Off::default(), 300);
    assert!(f.is_empty(), "{} fail; first {:?}", f.len(), f.first());
}

/// What each rule holds up (by hand: the findings in notes/whole-commits.md, Strip).
#[test]
#[ignore]
fn explore() {
    let offs = [
        ("all on", Off::default()),
        ("no carriers", Off { carriers: true, ..Off::default() }),
        ("no fewer-wins", Off { fewer: true, ..Off::default() }),
        ("no stand", Off { stand: true, ..Off::default() }),
        ("deletes on sealed", Off { sealed: true, ..Off::default() }),
        ("no cover strip", Off { no_cover_strip: true, ..Off::default() }),
        ("covered counts missing", Off { cover_missing: true, ..Off::default() }),
        ("no snapshot at K", Off { snap_at_k: true, ..Off::default() }),
        ("held blobs' lists only", Off { held_lists: true, ..Off::default() }),
        ("tables name occurring sessions only", Off { occurring: true, ..Off::default() }),
    ];
    for (name, off) in offs {
        let f = sweep(off, 3000);
        eprintln!("{name}: {} of 3000 fail; first {:?}", f.len(), f.first());
    }
}
