//! The cost harness (notes/fast-design.md section 4): every registered view is shown from its
//! `sample`, and what it reads and what a write then re-runs is checked generically, from the
//! recorded read sets. A kit test runs it over kit's views, an app test over the app's: a new view
//! is covered when it registers. Counts work, never time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::store::Data;
use crate::view::graph::{Costs, NodeReads};
use crate::view::keyed::steps;
use crate::view::{Block, Cx, QUERY, Section, Surface, Tree, ViewSpec, WindowState};
use crate::views::ViewType;
use osis::{Ak, DynamicAspectKey, Member, Tid, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// An aspect no view reads, on purpose.
const PROBE: &str = "x:probe.0";

/// Where a tree draws in a test: what each path shows, and the rows a change would touch.
#[derive(Default)]
pub struct Screen {
    models: HashMap<String, Section>,
    /// Rows the last changes built (the widget layer's `rows` counted without widgets).
    pub rows: u64,
}

fn entries(blocks: &[Block]) -> u64 {
    blocks.iter().map(|b| match b {
        Block::Entries(crate::view::Placed::Stream(v)) => v.len() as u64,
        Block::Entries(crate::view::Placed::Cards(r) | crate::view::Placed::Rows(r)) => r.entries.len() as u64,
        _ => 0,
    }).sum()
}

impl Surface for Screen {
    fn show(&mut self, path: &str, out: &Section) -> osis::Result<bool> {
        let Some(old) = self.models.insert(path.to_string(), out.clone()) else {
            self.rows += entries(&out.blocks);
            return Ok(true);
        };
        if old == *out {
            return Ok(false);
        }
        match steps(&old.blocks, &out.blocks) {
            Some(s) if old.foot == out.foot => {
                self.rows += s.iter().map(|(_, ops)| ops.iter().filter(|o| !matches!(o, crate::list::Op::Remove(_))).count() as u64).sum::<u64>();
                Ok(false)
            }
            _ => {
                self.rows += entries(&out.blocks);
                Ok(true)
            }
        }
    }
    fn gone(&mut self, path: &str) {
        self.models.remove(path);
    }
}

/// Every view of `d`'s registry shown from its `sample`, with a search typed and without. Returns
/// each failure; nothing means every view passed.
pub fn check_views(d: &Data) -> Vec<String> {
    let mut fails = Vec::new();
    let probe = |t: Tid, v: i64| {
        let mut w = d.db.write();
        w.at(t, DynamicAspectKey::untyped(Ak::new(PROBE).unwrap())).set(&Value::Int(v)).unwrap();
        w.commit().unwrap();
    };
    // a thing nothing shows: nothing reads it unless the view shows everything, then its address is
    let other = {
        let mut w = d.db.write();
        let t = w.create().unwrap();
        w.group(d.db.me()).add(Member::Item(t)).unwrap();
        w.commit().unwrap();
        t
    };
    probe(other, 0);
    let mut moved = 0;
    for v in d.registry.views.iter().copied() {
        for query in ["", "a"] {
            let t = (v.sample)(d);
            probe(t, 0);
            check_view(d, v, t, other, query, &mut fails, &mut moved);
        }
    }
    // a harness that moved nothing checked nothing
    if moved == 0 {
        fails.push("no address could be moved".into());
    }
    fails
}

fn check_view(d: &Data, v: &ViewType, t: Tid, other: Tid, query: &str, fails: &mut Vec<String>, total_moved: &mut usize) {
    let w = WindowState::default();
    Cx::new(d, &w, false);
    w.set_local(QUERY, query.to_string());
    let mut tree = Tree::default();
    let mut screen = Screen::default();
    let spec = ViewSpec::new(v.id, t);
    let name = format!("{}{}", v.id, if query.is_empty() { "" } else { "?" });
    let update = |tree: &mut Tree, screen: &mut Screen| {
        Cx::new(d, &w, false);
        tree.update(&w, screen)
    };
    if let Err(e) = tree.show(&w, &mut screen, "sample", &spec) {
        fails.push(format!("{name}: show: {e}"));
        return;
    }
    // what ran in setting it up is not a change
    update(&mut tree, &mut screen).unwrap();
    let snap = w.graph.snapshot();
    // no duplicates: within one node, no address read twice
    for n in &snap {
        for (a, c) in &n.reads {
            if *c > 1 {
                fails.push(format!("{name}: {} read {a} {c} times", n.key));
            }
        }
    }
    let run = |tree: &mut Tree, screen: &mut Screen, write: &dyn Fn()| -> (Vec<String>, Costs) {
        w.graph.take_costs();
        w.graph.record();
        write();
        d.db.settle();
        let r = update(tree, screen);
        if let Err(e) = r {
            return (vec![format!("update failed: {e}")], w.graph.take_costs());
        }
        (w.graph.recorded(), w.graph.take_costs())
    };
    let check_ran = |what: &str, ran: &[String], allowed: &BTreeSet<&str>, must: &[&str], fails: &mut Vec<String>| {
        let mut count = HashMap::new();
        for k in ran {
            *count.entry(k.as_str()).or_insert(0) += 1;
            if !allowed.contains(k.as_str()) && snap.iter().any(|n| n.key == *k) {
                fails.push(format!("{name}: {what}: ran {k}, which did not read it"));
            }
        }
        for (k, c) in count {
            if c > 1 {
                fails.push(format!("{name}: {what}: {k} ran {c} times"));
            }
        }
        for k in must {
            if !ran.iter().any(|r| r == k) {
                fails.push(format!("{name}: {what}: {k} read it and did not run"));
            }
        }
    };
    // a write nothing here read runs nothing at all
    if !snap.iter().any(|n| n.reads.iter().any(|(a, _)| a.contains(&other.to_string()))) {
        let (ran, c) = run(&mut tree, &mut screen, &|| set(d, other, PROBE, Value::Int(1)));
        set(d, other, PROBE, Value::Int(0));
        if !ran.is_empty() || c != Costs::default() {
            fails.push(format!("{name}: a write to another thing ran {ran:?} ({c:?})"));
        }
    }
    update(&mut tree, &mut screen).unwrap();
    // a write to an aspect of the subject no one reads runs only what reads the thing as a whole
    let whole: BTreeSet<&str> = closure(&snap, |n| n.reads.iter().any(|(a, _)| !a.starts_with("value ") && a.contains(&t.to_string())));
    let (ran, _) = run(&mut tree, &mut screen, &|| set(d, t, PROBE, Value::Int(1)));
    check_ran("a write to an unread aspect", &ran, &whole, &[], fails);
    set(d, t, PROBE, Value::Int(0));
    update(&mut tree, &mut screen).unwrap();
    // a write to an address that was read runs exactly what read it
    let addresses: BTreeSet<String> = snap.iter().flat_map(|n| n.reads.iter().map(|(a, _)| a.clone())).collect();
    let mut moved = 0;
    for a in &addresses {
        let Some((tid, ak, restore)) = perturb(d, a) else { continue };
        moved += 1;
        // and what reads the thing as a whole, which any write of its moves (`changed`, undo)
        let whole_of = |x: &str| !x.starts_with("value ") && x.contains(&tid.to_string());
        let allowed = closure(&snap, |n| n.reads.iter().any(|(x, _)| x == a || whole_of(x)));
        let readers: Vec<&str> = snap.iter().filter(|n| n.view && n.reads.iter().any(|(x, _)| x == a)).map(|n| n.key.as_str()).collect();
        let (ran, _) = run(&mut tree, &mut screen, &|| ());
        let after = w.graph.snapshot();
        let still: Vec<&str> = readers.into_iter().filter(|k| after.iter().any(|n| n.key == **k)).collect();
        check_ran(&format!("a write to {a}"), &ran, &allowed, &still, fails);
        put(d, tid, &ak, restore);
        update(&mut tree, &mut screen).unwrap();
    }
    *total_moved += moved;
}

/// The keys of the nodes `pick` matches and everything that depends on them.
fn closure(snap: &[NodeReads], pick: impl Fn(&NodeReads) -> bool) -> BTreeSet<&str> {
    let by: BTreeMap<&str, &NodeReads> = snap.iter().map(|n| (n.key.as_str(), n)).collect();
    let mut todo: Vec<&str> = snap.iter().filter(|n| pick(n)).map(|n| n.key.as_str()).collect();
    let mut seen = BTreeSet::new();
    while let Some(k) = todo.pop() {
        if seen.insert(k) && let Some(n) = by.get(k) {
            todo.extend(n.dependents.iter().map(String::as_str));
        }
    }
    seen
}

fn set(d: &Data, t: Tid, ak: &str, v: Value) {
    put(d, t, ak, Some(v));
}

fn put(d: &Data, t: Tid, ak: &str, v: Option<Value>) {
    let mut w = d.db.write();
    let k = DynamicAspectKey::untyped(Ak::new(ak).unwrap());
    match v {
        Some(v) => w.at(t, k).set(&v).unwrap(),
        None => w.at(t, k).remove().unwrap(),
    }
    w.commit().unwrap();
}

/// A write that changes what `address` reads (the same shape, one leaf differs); the address's
/// old state. `None`: not a kind of address this can move.
fn perturb(d: &Data, address: &str) -> Option<(Tid, String, Option<Value>)> {
    let mut p = address.split(' ');
    match (p.next()?, p.next()?) {
        ("value", t) => {
            let t: Tid = t.parse().ok()?;
            let ak = p.next()?.to_string();
            if p.next()? != "Path([])" {
                return None;
            }
            let old = d.db.at(t, DynamicAspectKey::untyped(Ak::new(&ak).ok()?)).get().ok()??;
            let new = mutated(&old)?;
            let mut w = d.db.write();
            w.at(t, DynamicAspectKey::untyped(Ak::new(&ak).ok()?)).set(&new).ok()?;
            w.commit().ok()?;
            Some((t, ak, Some(old)))
        }
        ("aspects", t) => {
            let t: Tid = t.parse().ok()?;
            let mut w = d.db.write();
            w.at(t, DynamicAspectKey::untyped(Ak::new("x:added.0").ok()?)).set(&Value::Int(1)).ok()?;
            w.commit().ok()?;
            Some((t, "x:added.0".into(), None))
        }
        _ => None,
    }
}

fn mutated(v: &Value) -> Option<Value> {
    Some(match v {
        Value::Bool(b) => Value::Bool(!b),
        Value::Int(i) => Value::Int(i + 1),
        Value::Str(s) => Value::Str(format!("{s}x")),
        Value::Enum(c, Some(b)) => Value::Enum(*c, Some(Box::new(mutated(b)?))),
        Value::List(items) => {
            for (i, x) in items.iter().enumerate() {
                if let Some(m) = mutated(x) {
                    let mut l = items.clone();
                    *l.get_mut(i)? = m;
                    return Some(Value::List(l));
                }
            }
            return None;
        }
        Value::Map(m) => {
            for (k, x) in m.iter() {
                if let Some(nx) = mutated(x) {
                    let mut c = m.clone();
                    c.insert(k.clone(), nx);
                    return Some(Value::Map(c));
                }
            }
            return None;
        }
        _ => return None,
    })
}
