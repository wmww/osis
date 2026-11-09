//! The window's dependency graph (notes/fast-design.md): one node type, a key, a value, a `ReadSet`
//! and a dirty flag. A view render is a node, `cx.memo(key, f)` is a node, every read through a
//! render's `db` is a node of its address, and a local cell (`Local`) is a node set from outside.
//! A node runs when asked for while dirty; a node whose new value equals its old stops propagation.
//! `Cx`/`Reader` hold a node's scope, so what runs inside `f` is what it depends on.
//!
//! Dirty marks: a node's `ReadSet` queues its id when a read answer changes (any thread, the
//! dispatcher). `drain` turns the queue into marks (`Dirty` on the node, `Check` on what depends on
//! it). Asking for a `Check` node validates its dependencies in the order read: the first whose value
//! moved since this node ran makes it `Dirty`; none, and it is `Clean` without running.

use crate::store::Reader;
use crate::view::{WindowInner, WindowState};
use osis::{ReadSet, Result};
use std::any::{Any, TypeId};
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};

type NodeId = u64;

/// A hashable, comparable key of any type (memos and reads key on what they read).
trait AnyKey: Any + Debug {
    fn dyn_hash(&self, h: &mut dyn Hasher);
    fn dyn_eq(&self, other: &dyn AnyKey) -> bool;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any + Debug + Hash + Eq> AnyKey for T {
    fn dyn_hash(&self, mut h: &mut dyn Hasher) {
        TypeId::of::<T>().hash(&mut h);
        self.hash(&mut h);
    }
    fn dyn_eq(&self, other: &dyn AnyKey) -> bool {
        other.as_any().downcast_ref::<T>() == Some(self)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Key(Box<dyn AnyKey>);

impl Hash for Key {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.0.dyn_hash(h);
    }
}
impl PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        self.0.dyn_eq(other.0.as_ref())
    }
}
impl Eq for Key {}
impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Clean,
    /// A dependency's value may have moved.
    Check,
    Dirty,
}

type Compute = Rc<dyn Fn(&Reader) -> Result<Rc<dyn Any>>>;

struct Node {
    key: Rc<Key>,
    value: Option<Rc<dyn Any>>,
    /// Bumped when the value differs: what a dependent compares against what it last saw.
    seq: u64,
    state: State,
    running: bool,
    /// `None`: a local cell, set from outside.
    compute: Option<Compute>,
    eq: fn(&dyn Any, &dyn Any) -> bool,
    set: Rc<ReadSet>,
    /// Dependencies in the order read, each with the seq it had.
    deps: Vec<(NodeId, u64)>,
    dependents: HashSet<NodeId>,
    /// The sweep mark it was last reached in.
    reached: u64,
}

fn eq_of<V: PartialEq + 'static>(a: &dyn Any, b: &dyn Any) -> bool {
    a.downcast_ref::<V>() == b.downcast_ref::<V>()
}

#[derive(Default)]
struct Inner {
    nodes: HashMap<NodeId, Node>,
    by_key: HashMap<Rc<Key>, NodeId>,
    next_id: NodeId,
    next_seq: u64,
    root: Option<NodeId>,
}

/// Where reads fired by the dispatcher (any thread) land.
struct Shared {
    queue: Mutex<Vec<NodeId>>,
    notify: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// A window's graph (`WindowState`).
pub struct Graph {
    inner: RefCell<Inner>,
    shared: Arc<Shared>,
    base: OnceCell<Reader>,
    log: RefCell<Option<Vec<String>>>,
    window: RefCell<Weak<WindowInner>>,
}

impl Default for Graph {
    fn default() -> Graph {
        Graph { inner: RefCell::default(), shared: Arc::new(Shared { queue: Mutex::default(), notify: Mutex::default() }), base: OnceCell::new(), log: RefCell::default(), window: RefCell::new(Weak::new()) }
    }
}

/// A node's place in the graph, held by the `Reader` running it.
#[derive(Clone)]
pub struct Scope {
    pub(crate) graph: Rc<Graph>,
    node: NodeId,
}

/// A piece of state not in osis, a node read like any other: scroll range, search query, the minute
/// tick. `name` is its key in the graph.
#[derive(Clone, Copy)]
pub struct Local<T: 'static> {
    name: &'static str,
    default: fn() -> T,
}

impl<T: 'static> Local<T> {
    pub const fn new(name: &'static str, default: fn() -> T) -> Local<T> {
        Local { name, default }
    }
}

impl Graph {
    /// What a read through the graph's `Reader`s is told to call when a node goes dirty (a read
    /// changed, on the dispatcher, or a local cell set).
    pub fn set_notify(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *lock(&self.shared.notify) = Some(f);
    }

    fn notify(&self) {
        if let Some(f) = lock(&self.shared.notify).clone() {
            f();
        }
    }

    pub(crate) fn set_window(&self, w: Weak<WindowInner>) {
        *self.window.borrow_mut() = w;
    }

    /// The window this graph belongs to.
    pub(crate) fn window(&self) -> Option<WindowState> {
        self.window.borrow().upgrade().map(WindowState::from)
    }

    /// Records which keys run (tests' work counts), from now until `recorded` is taken.
    pub fn record(&self) {
        *self.log.borrow_mut() = Some(Vec::new());
    }

    /// The keys that ran since `record`.
    pub fn recorded(&self) -> Vec<String> {
        self.log.borrow_mut().take().unwrap_or_default()
    }

    /// Nodes held (a test's view of what the sweep frees).
    pub fn len(&self) -> usize {
        self.inner.borrow().nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The node every root context reads through.
    pub(crate) fn begin(this: &Rc<Graph>, base: &Reader) -> Option<(Scope, Rc<ReadSet>)> {
        let _ = this.base.get_or_init(|| base.clone());
        Graph::drain(this);
        let mut i = this.inner.borrow_mut();
        let root = match i.root {
            Some(r) => r,
            None => {
                let r = new_node(&mut i, &this.shared, "root".to_string(), None, eq_of::<()>);
                i.root = Some(r);
                r
            }
        };
        let set = i.nodes.get(&root)?.set.clone();
        Some((Scope { graph: this.clone(), node: root }, set))
    }

    /// Moves what the dispatcher queued into dirty marks.
    pub fn drain(this: &Rc<Graph>) {
        let q = std::mem::take(&mut *lock(&this.shared.queue));
        let mut i = this.inner.borrow_mut();
        for id in q {
            mark_dirty(&mut i, id);
        }
    }

    /// Starts a pass: the root reads and rendered nodes of the last one no longer hold anything.
    pub fn begin_pass(this: &Rc<Graph>) {
        Graph::drain(this);
        let mut i = this.inner.borrow_mut();
        let Some(root) = i.root else { return };
        clear_deps(&mut i, root);
    }

    /// Ends a pass: the root's reads are what it listens to, and what the pass did not reach goes
    /// (its listeners with it).
    pub fn end_pass(&self) {
        let mut i = self.inner.borrow_mut();
        let Some(root) = i.root else { return };
        if let Some(n) = i.nodes.get(&root) {
            n.set.sweep();
        }
        i.next_seq += 1;
        let mark = i.next_seq;
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            let Some(n) = i.nodes.get_mut(&id) else { continue };
            if n.reached == mark {
                continue;
            }
            n.reached = mark;
            stack.extend(n.deps.iter().map(|d| d.0));
        }
        let gone: Vec<NodeId> = i.nodes.iter().filter(|(_, n)| n.reached != mark && n.compute.is_some()).map(|(k, _)| *k).collect();
        for id in gone {
            if let Some(n) = i.nodes.remove(&id) {
                i.by_key.remove(&*n.key);
                for (d, _) in n.deps {
                    if let Some(x) = i.nodes.get_mut(&d) {
                        x.dependents.remove(&id);
                    }
                }
            }
        }
    }

    /// The value of `key`, computed by `f` when it has to be; `parent` depends on it. A node asked
    /// for while it runs is a cycle: an error, nothing cached.
    pub(crate) fn get<K, V>(this: &Rc<Graph>, parent: &Scope, key: K, f: impl Fn(&Reader) -> Result<V> + 'static) -> Result<Rc<V>>
    where
        K: Any + Debug + Hash + Eq,
        V: PartialEq + 'static,
    {
        let id = {
            let mut i = this.inner.borrow_mut();
            let k = Rc::new(Key(Box::new(key)));
            match i.by_key.get(&*k) {
                Some(&id) => id,
                None => {
                    let compute: Compute = Rc::new(move |r: &Reader| Ok(Rc::new(f(r)?) as Rc<dyn Any>));
                    insert_node(&mut i, &this.shared, k, Some(compute), eq_of::<V>)
                }
            }
        };
        if this.inner.borrow().nodes.get(&id).is_some_and(|n| n.running) {
            return Err(osis::Error::Invalid("a value that depends on itself".into()));
        }
        let up = Graph::bring_up(this, id);
        let mut i = this.inner.borrow_mut();
        // the dependency stands even when it failed: a parent that handles the error reruns with it
        let seq = i.nodes.get(&id).ok_or_else(gone)?.seq;
        add_dep(&mut i, parent.node, id, seq);
        up?;
        let value = i.nodes.get(&id).ok_or_else(gone)?.value.clone().ok_or_else(gone)?;
        drop(i);
        value.downcast::<V>().map_err(|_| osis::Error::Invalid("a graph key of two value types".into()))
    }

    /// Brings `id` up to date: validated, and run if that left it dirty.
    fn bring_up(this: &Rc<Graph>, id: NodeId) -> Result<()> {
        let state = |this: &Rc<Graph>| -> Result<(State, bool)> {
            let i = this.inner.borrow();
            let n = i.nodes.get(&id).ok_or_else(gone)?;
            Ok((n.state, n.running))
        };
        let (first, running) = state(this)?;
        if running {
            return Err(osis::Error::Invalid("a value that depends on itself".into()));
        }
        if first == State::Check {
            Graph::validate(this, id)?;
        }
        // after validating `Check` is an answer too: settled, over a failure it handled
        if state(this)?.0 == State::Dirty { Graph::run(this, id) } else { Ok(()) }
    }

    /// A `Check` node: `Dirty` if a dependency it saw has moved or failed, else `Clean`.
    fn validate(this: &Rc<Graph>, id: NodeId) -> Result<()> {
        let deps = {
            let i = this.inner.borrow();
            i.nodes.get(&id).ok_or_else(gone)?.deps.clone()
        };
        for (d, seen) in deps {
            let up = Graph::bring_up(this, d);
            let mut i = this.inner.borrow_mut();
            if up.is_err() || i.nodes.get(&d).ok_or_else(gone)?.seq != seen {
                i.nodes.get_mut(&id).ok_or_else(gone)?.state = State::Dirty;
                return Ok(());
            }
        }
        settle(&mut this.inner.borrow_mut(), id);
        Ok(())
    }

    /// Runs a node's computation under its scope; an equal value keeps the seq (dependents stay).
    fn run(this: &Rc<Graph>, id: NodeId) -> Result<()> {
        let (compute, set, eq) = {
            let mut i = this.inner.borrow_mut();
            clear_deps(&mut i, id);
            let n = i.nodes.get_mut(&id).ok_or_else(gone)?;
            n.running = true;
            let Some(c) = n.compute.clone() else {
                n.running = false;
                n.state = State::Clean;
                return Ok(());
            };
            if let Some(l) = this.log.borrow_mut().as_mut() {
                l.push(format!("{:?}", n.key));
            }
            (c, n.set.clone(), n.eq)
        };
        let base = this.base.get().cloned().ok_or_else(gone)?;
        let scope = Scope { graph: this.clone(), node: id };
        let r = base.scoped(&set, scope);
        let out = compute(&r);
        let mut i = this.inner.borrow_mut();
        i.next_seq += 1;
        let seq = i.next_seq;
        let n = i.nodes.get_mut(&id).ok_or_else(gone)?;
        n.running = false;
        n.set.sweep();
        let v = match out {
            Ok(v) => v,
            Err(e) => {
                n.state = State::Dirty;
                return Err(e);
            }
        };
        let changed = n.value.as_deref().is_none_or(|old| !eq(old, &*v));
        if changed {
            n.value = Some(v);
            n.seq = seq;
        }
        settle(&mut i, id);
        Ok(())
    }

    /// A local cell's value (`Local::default` until set); `parent` depends on it.
    pub(crate) fn local<T: Clone + PartialEq + 'static>(this: &Rc<Graph>, parent: &Scope, cell: Local<T>) -> Result<T> {
        let id = {
            let mut i = this.inner.borrow_mut();
            local_node::<T>(&mut i, &this.shared, cell.name, cell.default)
        };
        let mut i = this.inner.borrow_mut();
        let (v, seq) = {
            let n = i.nodes.get(&id).ok_or_else(gone)?;
            (n.value.clone().ok_or_else(gone)?, n.seq)
        };
        add_dep(&mut i, parent.node, id, seq);
        v.downcast::<T>().map(|v| (*v).clone()).map_err(|_| osis::Error::Invalid("a local cell of two types".into()))
    }

    /// A local cell's value, read outside any node (the shell).
    pub fn peek<T: Clone + PartialEq + 'static>(&self, cell: Local<T>) -> T {
        let mut i = self.inner.borrow_mut();
        let id = local_node::<T>(&mut i, &self.shared, cell.name, cell.default);
        i.nodes.get(&id).and_then(|n| n.value.as_deref()).and_then(|v| v.downcast_ref::<T>()).cloned().unwrap_or_else(|| (cell.default)())
    }

    /// Sets a local cell; what read it goes dirty when the value differs.
    pub fn set_local<T: Clone + PartialEq + 'static>(&self, cell: Local<T>, v: T) {
        let mut i = self.inner.borrow_mut();
        let id = local_node::<T>(&mut i, &self.shared, cell.name, cell.default);
        i.next_seq += 1;
        let seq = i.next_seq;
        let Some(n) = i.nodes.get_mut(&id) else { return };
        if n.value.as_deref().is_some_and(|old| old.downcast_ref::<T>() == Some(&v)) {
            return;
        }
        n.value = Some(Rc::new(v));
        n.seq = seq;
        mark_dependents(&mut i, id);
        drop(i);
        self.notify();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn gone() -> osis::Error {
    osis::Error::Invalid("a graph node swept while in use".into())
}

fn insert_node(i: &mut Inner, shared: &Arc<Shared>, key: Rc<Key>, compute: Option<Compute>, eq: fn(&dyn Any, &dyn Any) -> bool) -> NodeId {
    i.next_id += 1;
    let id = i.next_id;
    let s = shared.clone();
    let set = Rc::new(ReadSet::new(move |_| {
        lock(&s.queue).push(id);
        if let Some(f) = lock(&s.notify).clone() {
            f();
        }
    }));
    i.by_key.insert(key.clone(), id);
    i.nodes.insert(id, Node { key, value: None, seq: 0, state: State::Dirty, running: false, compute, eq, set, deps: Vec::new(), dependents: HashSet::new(), reached: 0 });
    id
}

fn new_node(i: &mut Inner, shared: &Arc<Shared>, name: String, compute: Option<Compute>, eq: fn(&dyn Any, &dyn Any) -> bool) -> NodeId {
    insert_node(i, shared, Rc::new(Key(Box::new(("node", name)))), compute, eq)
}

fn local_node<T: Clone + PartialEq + 'static>(i: &mut Inner, shared: &Arc<Shared>, name: &'static str, default: fn() -> T) -> NodeId {
    let k = Rc::new(Key(Box::new(("local", name))));
    if let Some(&id) = i.by_key.get(&*k) {
        return id;
    }
    let id = insert_node(i, shared, k, None, eq_of::<T>);
    if let Some(n) = i.nodes.get_mut(&id) {
        n.value = Some(Rc::new(default()));
        n.state = State::Clean;
    }
    id
}

/// Done computing: `Clean`, unless a dependency whose failure it handled is still not (`Check`, so
/// it is asked again). A node is never `Clean` over one that is not.
fn settle(i: &mut Inner, id: NodeId) {
    let clean = i.nodes.get(&id).is_some_and(|n| n.deps.iter().all(|(d, _)| i.nodes.get(d).is_none_or(|x| x.state == State::Clean)));
    if let Some(n) = i.nodes.get_mut(&id) {
        n.state = if clean { State::Clean } else { State::Check };
    }
}

fn clear_deps(i: &mut Inner, id: NodeId) {
    let Some(n) = i.nodes.get_mut(&id) else { return };
    for (d, _) in std::mem::take(&mut n.deps) {
        if let Some(x) = i.nodes.get_mut(&d) {
            x.dependents.remove(&id);
        }
    }
}

fn add_dep(i: &mut Inner, parent: NodeId, child: NodeId, seq: u64) {
    if let Some(n) = i.nodes.get_mut(&parent) {
        n.deps.push((child, seq));
    }
    if let Some(n) = i.nodes.get_mut(&child) {
        n.dependents.insert(parent);
    }
}

fn mark_dirty(i: &mut Inner, id: NodeId) {
    let Some(n) = i.nodes.get_mut(&id) else { return };
    n.state = State::Dirty;
    mark_dependents(i, id);
}

/// Every dependent, recursively, `Check` unless already not `Clean` (then so are its dependents).
fn mark_dependents(i: &mut Inner, id: NodeId) {
    let mut todo: Vec<NodeId> = i.nodes.get(&id).map(|n| n.dependents.iter().copied().collect()).unwrap_or_default();
    while let Some(d) = todo.pop() {
        let Some(n) = i.nodes.get_mut(&d) else { continue };
        if n.state == State::Clean {
            n.state = State::Check;
            todo.extend(n.dependents.iter().copied());
        }
    }
}

