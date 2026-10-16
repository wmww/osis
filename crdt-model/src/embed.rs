//! Lattice embeddings (spec §7).
use crate::stamp::{max_opt, Dot, Source, Stamp};
use crate::state::{Anchor, BagKind, Composite, Content, Elem, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

/// Embed `a` into encoding `target`, if an edge exists for `a`'s encoding and value type.
pub fn embed(a: &Frag, target: u8) -> Option<Frag> {
    let (reset, write) = match a {
        Frag::Register { reset, write } => (reset.clone(), write.clone()),
        _ => return None,
    };
    match target {
        1 | 2 | 3 => {
            let kind = match target {
                1 => BagKind::Counter,
                2 => BagKind::Max,
                _ => BagKind::Min,
            };
            let mut elems = BTreeMap::new();
            let mut written = None;
            let mut r = reset;
            if let Some((s, v)) = write {
                if !matches!(v, Value::Int(_) | Value::Float(_)) {
                    return None;
                }
                r = max_opt(r, Some(s.clone()));
                written = Some(s.clone());
                elems.insert(s.dot.clone(), Elem { reset: None, frag: Some(Box::new(Frag::Register { reset: None, write: Some((s, v)) })) });
            }
            Some(Frag::Bag { kind, c: Composite { reset: r, written }, elems })
        }
        9 => {
            let mut elems = BTreeMap::new();
            let mut written = None;
            let mut r = reset;
            if let Some((s, v)) = write {
                let text = match v {
                    Value::Str(t) => t,
                    _ => return None,
                };
                r = max_opt(r, Some(s.clone()));
                written = Some(s.clone());
                let src = Source::Derived(Box::new(s.dot.clone()));
                let mut prev = Anchor::Head;
                for (i, ch) in text.chars().enumerate() {
                    let dot = Dot { source: src.clone(), ctr: i as u64 + 1 };
                    let st = Stamp { ts: s.ts, dot: dot.clone() };
                    elems.insert(dot.clone(), SeqElem::new(st, prev, Content::Char(ch)));
                    prev = Anchor::Dot(dot);
                }
            }
            Some(Frag::Seq { text: true, c: Composite { reset: r, written }, elems })
        }
        _ => None,
    }
}
