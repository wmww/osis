//! Lattice embeddings (spec §7).
use crate::stamp::{max_opt, Dot, Source, Stamp};
use crate::state::{Anchor, BagKind, Composite, Content, Elem, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

/// Embed `a` into encoding `target`, if an edge exists. Every edge from a register is total, so a value-less write
/// (§4.7) embeds exactly as its valued copy would after stripping: a value that does not fit the target (or none)
/// leaves only the reset (text) or a contribution that reads as nothing (bags).
pub fn embed(a: &Frag, target: u8) -> Option<Frag> {
    let (reset, write) = match a {
        Frag::Register { reset, write } => (reset.clone(), write.clone()),
        _ => return None,
    };
    let r = max_opt(reset, write.as_ref().map(|w| w.0.clone()));
    let c = Composite { reset: r, w: None };
    match target {
        1 | 2 | 3 => {
            let kind = match target {
                1 => BagKind::Counter,
                2 => BagKind::Max,
                _ => BagKind::Min,
            };
            let mut elems = BTreeMap::new();
            if let Some((s, v)) = write {
                elems.insert(s.dot.clone(), Elem { reset: None, frag: Some(Box::new(Frag::Register { reset: None, write: Some((s, v)) })) });
            }
            Some(Frag::Bag { kind, c, elems })
        }
        9 => {
            let mut elems = BTreeMap::new();
            if let Some((s, Some(Value::Str(text)))) = write {
                let src = Source::Derived(Box::new(s.dot.clone()));
                let mut prev = Anchor::Head;
                for (i, ch) in text.chars().enumerate() {
                    let dot = Dot { source: src.clone(), ctr: i as u64 + 1 };
                    let st = Stamp { ts: s.ts, dot: dot.clone() };
                    elems.insert(dot.clone(), SeqElem::new(st, prev, Content::Char(ch)));
                    prev = Anchor::Dot(dot);
                }
            }
            Some(Frag::Seq { text: true, c, elems })
        }
        _ => None,
    }
}
