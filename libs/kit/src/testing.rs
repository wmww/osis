//! The cost harness (notes/fast-design.md section 4): every registered view is shown from its
//! `sample`, and what it reads and what a write then re-runs is checked generically, from the
//! recorded read sets. A kit test runs it over kit's views, an app test over the app's: a new view
//! is covered when it registers. Counts work, never time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::store::Data;
use crate::view::graph::{Costs, NodeReads};
use crate::view::keyed::steps;
use crate::view::{Block, Cx, QUERY, Section, Surface, TICK, Tree, ViewSpec, WindowState};
use crate::views::ViewType;
use osis::{Ak, DynamicAspectKey, Member, Tid, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// An aspect no view reads, on purpose.
const PROBE: &str = "x:probe.0";
/// An aspect a write adds to a thing, moving what reads its set of aspects.
const ADDED: &str = "x:added.0";
/// The size a list source is grown to for the scale check, and that times ten.
const SMALL: usize = 10;
const LARGE: usize = 100;
/// How much a change may cost more at `LARGE` than at `SMALL` (a fixed ratio; what scales passes at
/// any number, a linear cost fails at 10).
const SCALE_RATIO: u64 = 2;
/// Rows a list holds beyond its window: its "new" tile, a page landing past the limit.
const WINDOW_SLACK: u64 = 2;

/// Where a tree draws in a test: what each path shows, and the rows a change would touch.
#[derive(Default)]
pub struct Screen {
    models: HashMap<String, Section>,
    /// Rows the last changes built (the widget layer's `rows` counted without widgets).
    pub rows: u64,
}

fn entries(blocks: &[Block]) -> u64 {
    blocks.iter().map(|b| match b {
        Block::List(l) => l.rows().len() as u64,
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
    let spare = crate::facets::create(d, "tag").unwrap();
    for v in d.registry.views.iter().copied() {
        let mut reached = Reached::default();
        for query in ["", "a"] {
            let t = (v.sample)(d);
            probe(t, 0);
            check_view(d, v, t, (other, spare), query, &mut fails, &mut reached);
        }
        // a sample that shows nothing or whose reads cannot be moved checked nothing
        if !reached.content {
            fails.push(format!("{}: its sample shows nothing", v.id));
        }
        if !reached.moved {
            fails.push(format!("{}: nothing it read could be moved", v.id));
        }
    }
    // last: what they grow would make the checks above walk more things
    for v in d.registry.views.iter().copied() {
        if let Some(grow) = v.grow {
            check_scale(d, v, grow, &mut fails);
        }
    }
    fails
}

/// Shows `v` grown to `n`, then adds one more to what it lists. The rows built by the showing and
/// the work of the addition: renders, memo runs, addresses those runs read, rows.
fn scale_run(d: &Data, v: &ViewType, grow: fn(&Data, Tid, usize), n: usize) -> (u64, u64, u64) {
    let t = (v.sample)(d);
    grow(d, t, n);
    let w = WindowState::default();
    // for a view of what the search finds: everything grown matches
    w.set_local(QUERY, "grown".to_string());
    Cx::new(d, &w, false);
    let mut tree = Tree::default();
    let mut screen = Screen::default();
    tree.show(&w, &mut screen, "scale", &ViewSpec::new(v.id, t)).unwrap();
    Cx::new(d, &w, false);
    tree.update(&w, &mut screen).unwrap();
    let shown = std::mem::take(&mut screen.rows);
    w.graph.take_costs();
    w.graph.record();
    grow(d, t, 1);
    d.db.settle();
    Cx::new(d, &w, false);
    tree.update(&w, &mut screen).unwrap();
    let ran: BTreeSet<String> = w.graph.recorded().into_iter().collect();
    let c = w.graph.take_costs();
    let reads: u64 = w.graph.snapshot().iter().filter(|n| ran.contains(&n.key)).map(|n| n.reads.iter().map(|(_, c)| u64::from(*c)).sum::<u64>()).sum();
    (shown, c.renders + c.memo_runs + reads, screen.rows)
}

/// Scale and window: what is shown is at most a window whatever is listed, and adding one row
/// costs the same at n and 10n. A chat's grown messages quote nothing: a quote's walk grows until
/// signal edits land (notes/fast-design.md step 9), the one exemption.
fn check_scale(d: &Data, v: &ViewType, grow: fn(&Data, Tid, usize), fails: &mut Vec<String>) {
    let (shown_s, work_s, rows_s) = scale_run(d, v, grow, SMALL);
    let (shown_l, work_l, rows_l) = scale_run(d, v, grow, LARGE);
    let bound = crate::view::paged::WINDOW as u64 + WINDOW_SLACK;
    for (n, shown) in [(SMALL, shown_s), (LARGE, shown_l)] {
        if shown > bound {
            fails.push(format!("{}: {shown} rows built showing {n}, at most {bound}", v.id));
        }
    }
    if rows_l > 2 || rows_s > 2 {
        fails.push(format!("{}: adding a row built {rows_s} rows at {SMALL}, {rows_l} at {LARGE}", v.id));
    }
    if work_l > work_s.max(1) * SCALE_RATIO {
        fails.push(format!("{}: adding a row cost {work_s} at {SMALL} and {work_l} at {LARGE}", v.id));
    }
}

/// What a view's sample reached, over its runs.
#[derive(Default)]
struct Reached {
    content: bool,
    moved: bool,
}

/// What `t` and the things read hold, in the form a write can move: `(thing, aspect)`.
fn movable(d: &Data, tids: &BTreeSet<Tid>) -> BTreeSet<(Tid, String)> {
    tids.iter()
        .flat_map(|t| d.db.aspects(*t).unwrap_or_default().into_iter().map(move |ak| (*t, ak.to_string())))
        .collect()
}

/// A thing's id in an address.
fn tids_in(address: &str) -> Vec<Tid> {
    address.split([' ', '(', ')']).filter_map(|w| w.parse().ok()).collect()
}

fn check_view(d: &Data, v: &ViewType, t: Tid, (other, spare): (Tid, Tid), query: &str, fails: &mut Vec<String>, reached: &mut Reached) {
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
    reached.content |= screen.models.values().any(|m| !m.blocks.is_empty());
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
    // what is on screen is what a fresh render of the current data shows: a read no one listens
    // to leaves it stale
    let fresh = |screen: &Screen| -> Vec<String> {
        let w2 = WindowState::default();
        w2.set_local(TICK, w.graph.peek(TICK));
        w2.set_local(QUERY, query.to_string());
        Cx::new(d, &w2, false);
        let (mut t2, mut s2) = (Tree::default(), Screen::default());
        if let Err(e) = t2.show(&w2, &mut s2, "sample", &spec) {
            return vec![format!("fresh render: {e}")];
        }
        Cx::new(d, &w2, false);
        if let Err(e) = t2.update(&w2, &mut s2) {
            return vec![format!("fresh render: {e}")];
        }
        let shown = |m: &HashMap<String, Section>| m.iter().map(|(k, v)| format!("{k}: {v:?}")).collect::<BTreeSet<_>>();
        shown(&screen.models).symmetric_difference(&shown(&s2.models)).cloned().collect()
    };
    let addresses: BTreeSet<String> = snap.iter().flat_map(|n| n.reads.iter().map(|(a, _)| a.clone())).collect();
    // a write moves what reads the thing whole (`changed`, its commits) and the aspect's address
    let whole = |x: &str, tid: Tid| (x.starts_with("changed ") || x.starts_with("Writes")) && x.contains(&tid.to_string());
    let mut tids: BTreeSet<Tid> = addresses.iter().flat_map(|a| tids_in(a)).collect();
    tids.insert(t);
    let mut moved = false;
    let mut check_write = |tree: &mut Tree, screen: &mut Screen, what: String, allowed: BTreeSet<&str>, must: Vec<&str>| {
        let (ran, _) = run(tree, screen, &|| ());
        let after = w.graph.snapshot();
        let still: Vec<&str> = must.into_iter().filter(|k| after.iter().any(|n| n.key == **k)).collect();
        check_ran(&what, &ran, &allowed, &still, fails);
        for d in fresh(screen) {
            fails.push(format!("{name}: {what}: the screen is stale: {d}"));
        }
    };
    // each thing's every aspect, read or not: the writes a view must hear or must not care about
    for (tid, ak) in movable(d, &tids) {
        let Some(old) = d.db.at(tid, DynamicAspectKey::untyped(Ak::new(&ak).unwrap())).get().ok().flatten() else { continue };
        let Some(new) = mutated(&old) else { continue };
        if !try_put(d, tid, &ak, Some(new)) {
            continue;
        }
        moved = true;
        let address = format!("value {tid} {ak} Path([])");
        let prefix = format!("value {tid} {ak} ");
        let allowed = closure(&snap, |n| n.reads.iter().any(|(x, _)| x.contains(&prefix) || whole(x, tid)));
        let readers: Vec<&str> = snap.iter().filter(|n| n.view && n.reads.iter().any(|(x, _)| *x == address)).map(|n| n.key.as_str()).collect();
        check_write(&mut tree, &mut screen, format!("a write to {address}"), allowed, readers);
        put(d, tid, &ak, Some(old));
        update(&mut tree, &mut screen).unwrap();
    }
    // the set of aspects, and what groups a thing is in
    for a in &addresses {
        if let Some(rest) = a.strip_prefix("aspects ") {
            let Ok(tid) = rest.parse::<Tid>() else { continue };
            if !try_put(d, tid, ADDED, Some(Value::Int(1))) {
                continue;
            }
            moved = true;
            let allowed = closure(&snap, |n| n.reads.iter().any(|(x, _)| x == a || whole(x, tid)));
            let readers: Vec<&str> = snap.iter().filter(|n| n.view && n.reads.iter().any(|(x, _)| x == a)).map(|n| n.key.as_str()).collect();
            check_write(&mut tree, &mut screen, format!("a write to {a}"), allowed, readers);
            put(d, tid, ADDED, None);
            update(&mut tree, &mut screen).unwrap();
        } else if let Some(rest) = a.strip_prefix("groups_of ") {
            let Ok(tid) = rest.parse::<Tid>() else { continue };
            if !member(d, spare, tid, true) {
                continue;
            }
            moved = true;
            let spare_s = spare.to_string();
            let allowed = closure(&snap, |n| n.reads.iter().any(|(x, _)| x == a || x.contains(&spare_s) || whole(x, tid)));
            let readers: Vec<&str> = snap.iter().filter(|n| n.view && n.reads.iter().any(|(x, _)| x == a)).map(|n| n.key.as_str()).collect();
            check_write(&mut tree, &mut screen, format!("a write to {a}"), allowed, readers);
            member(d, spare, tid, false);
            update(&mut tree, &mut screen).unwrap();
        }
    }
    drop(check_write);
    reached.moved |= moved;
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

/// `put`, for a write the store may refuse (not every aspect read can be written here).
fn try_put(d: &Data, t: Tid, ak: &str, v: Option<Value>) -> bool {
    let Ok(ak) = Ak::new(ak) else { return false };
    let k = DynamicAspectKey::untyped(ak);
    let mut w = d.db.write();
    let set = match &v {
        Some(v) => w.at(t, k).set(v),
        None => w.at(t, k).remove(),
    };
    set.is_ok() && w.commit().is_ok()
}

/// `t` put in or taken out of the group `g`.
fn member(d: &Data, g: Tid, t: Tid, add: bool) -> bool {
    if g == t {
        return false;
    }
    let mut w = d.db.write();
    let changed = if add { w.group(g).add(Member::Item(t)) } else { w.group(g).remove(Member::Item(t)) };
    changed.is_ok() && w.commit().is_ok()
}

fn mutated(v: &Value) -> Option<Value> {
    Some(match v {
        Value::Bool(b) => Value::Bool(!b),
        Value::Int(i) => Value::Int(i.wrapping_add(1)),
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
