//! Greenfield model of thing lifetimes by reference (issues/thing-lifetimes.md). Not wired into
//! `evaluate`: it is the oracle for the engine's judgment and its work list when they are built.
//!
//! The rule: a thing with no list is standalone and kept. A thing with a list is kept while some
//! listed retainer is kept and references it, or cannot be judged (not held, not readable). A
//! node drops only what it holds, may end, and judges unreachable from what it holds.
//!
//! Abstracted: what "references" reads (a tid in the retainer's kept data), validity (only valid
//! writes reach a view), the right to end (a set of things), hearing labels out (a `View` is a
//! node's data once heard out; `view_of` shows what a part-received commit set does instead).
use std::collections::BTreeSet;

pub type T = usize;
pub type Set = BTreeSet<T>;

/// What a node holds of one thing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Held {
    /// Held and readable: its list (`None`: standalone) and the things its kept data references.
    Known { list: Option<Set>, refs: Set },
    /// Ended, and the node holds what shows it.
    Ended,
    /// Not held, not readable, or ended with nothing left to show it.
    Unknown,
}
pub type View = Vec<Held>;

/// The held things the node cannot judge unreachable: the least set holding every standalone
/// thing and every thing with a listed retainer that is unknown, or in the set and referencing it.
pub fn kept(v: &View) -> Set {
    let mut k = Set::new();
    loop {
        let before = k.len();
        for (x, h) in v.iter().enumerate() {
            let Held::Known { list, .. } = h else { continue };
            let keep = match list {
                None => true,
                Some(l) => l.iter().any(|&r| match &v[r] {
                    Held::Unknown => true,
                    Held::Ended => false,
                    Held::Known { refs, .. } => refs.contains(&x) && k.contains(&r),
                }),
            };
            if keep {
                k.insert(x);
            }
        }
        if k.len() == before {
            return k;
        }
    }
}

/// The held things judged unreachable: what the node drops where it may end them.
pub fn unreachable(v: &View) -> Set {
    let k = kept(v);
    (0..v.len()).filter(|x| matches!(v[*x], Held::Known { .. }) && !k.contains(x)).collect()
}

/// A second reading, for a view with nothing unknown: what a walk down from the standalone
/// things reaches, along R to X where R references X and X lists R.
pub fn reached_down(v: &View) -> Set {
    let mut seen: Set = (0..v.len()).filter(|x| matches!(&v[*x], Held::Known { list: None, .. })).collect();
    let mut stack: Vec<T> = seen.iter().copied().collect();
    while let Some(r) = stack.pop() {
        let Held::Known { refs, .. } = &v[r] else { continue };
        for &x in refs {
            if let Held::Known { list: Some(l), .. } = &v[x] {
                if l.contains(&r) && seen.insert(x) {
                    stack.push(x);
                }
            }
        }
    }
    seen
}

/// The judgment as an engine makes it for one thing: a search up the lists through retainers
/// that reference the thing below, stopping at the first standalone or unknown thing.
/// `true`: unreachable. Costs the things it visits.
pub fn walk(v: &View, x: T) -> bool {
    if !matches!(v[x], Held::Known { .. }) {
        return false;
    }
    let mut seen = Set::from([x]);
    let mut stack = vec![x];
    while let Some(y) = stack.pop() {
        let Held::Known { list, .. } = &v[y] else { unreachable!() };
        let Some(list) = list else { return false };
        for &r in list {
            match &v[r] {
                Held::Unknown => return false,
                Held::Ended => {}
                Held::Known { refs, .. } => {
                    if refs.contains(&y) && seen.insert(r) {
                        stack.push(r);
                    }
                }
            }
        }
    }
    true
}

/// One part of a commit; a commit's parts on things a node holds apply together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    Create(T),
    /// The whole list (`None`: the aspect removed).
    List(T, Option<Set>),
    /// Everything the thing's kept data references after the write.
    Refs(T, Set),
    End(T),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub ts: u64,
    pub parts: Vec<Part>,
}

/// What a node holding these commits holds of `n` things: the later write wins, an end is
/// final, and a part on a thing whose creation is not held is not held.
pub fn view_of(n: usize, held: &[&Commit]) -> View {
    let mut v: View = vec![Held::Unknown; n];
    let mut c: Vec<&Commit> = held.to_vec();
    c.sort_by_key(|c| c.ts);
    for part in c.iter().flat_map(|c| &c.parts) {
        if let Part::Create(x) = part {
            v[*x] = Held::Known { list: None, refs: Set::new() };
        }
    }
    for part in c.iter().flat_map(|c| &c.parts) {
        match part {
            Part::List(x, l) => {
                if let Held::Known { list, .. } = &mut v[*x] {
                    *list = l.clone();
                }
            }
            Part::Refs(x, r) => {
                if let Held::Known { refs, .. } = &mut v[*x] {
                    *refs = r.clone();
                }
            }
            _ => {}
        }
    }
    for part in c.iter().flat_map(|c| &c.parts) {
        if let Part::End(x) = part {
            v[*x] = Held::Ended;
        }
    }
    v
}

/// A change to what a node holds or may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    List(T, Option<Set>),
    Refs(T, Set),
    /// Ended by someone else, or by expiry.
    End(T),
    /// Read access lost, or the thing forgotten.
    Lose(T),
    /// The thing arrives, or becomes readable.
    Learn(T, Option<Set>, Set),
    /// The right to end the thing, gained or lost.
    Right(T, bool),
}

/// A node judging incrementally: each change queues what it touches, and `settle` judges the
/// queue. `pending` is its only kept state: the things judged unreachable that it may not end.
#[derive(Clone, Debug)]
pub struct Node {
    pub view: View,
    pub rights: Set,
    pub pending: Set,
    queue: Vec<T>,
    /// Things judged, for cost checks.
    pub judged: usize,
}

impl Node {
    pub fn new(n: usize) -> Node {
        Node { view: vec![Held::Unknown; n], rights: Set::new(), pending: Set::new(), queue: Vec::new(), judged: 0 }
    }

    /// The things listing `x`: the index's rows under `x` from lists.
    fn listers(&self, x: T) -> Vec<T> {
        (0..self.view.len()).filter(|y| matches!(&self.view[*y], Held::Known { list: Some(l), .. } if l.contains(&x))).collect()
    }

    /// The listers of `x` that `x` references: whose judgment follows `x`'s.
    fn below(&self, x: T) -> Vec<T> {
        let Held::Known { refs, .. } = &self.view[x] else { return Vec::new() };
        self.listers(x).into_iter().filter(|y| refs.contains(y)).collect()
    }

    pub fn apply(&mut self, e: Event) {
        match e {
            Event::List(x, l) => {
                if let Held::Known { list, .. } = &mut self.view[x] {
                    *list = l;
                    self.queue.push(x);
                }
            }
            Event::Refs(x, r) => {
                if let Held::Known { refs, .. } = &mut self.view[x] {
                    let changed: Vec<T> = refs.symmetric_difference(&r).copied().collect();
                    *refs = r;
                    self.queue.extend(changed);
                }
            }
            Event::End(x) => {
                self.view[x] = Held::Ended;
                self.pending.remove(&x);
                self.queue.extend(self.listers(x));
            }
            Event::Lose(x) => {
                self.view[x] = Held::Unknown;
                self.pending.remove(&x);
                self.queue.extend(self.listers(x));
            }
            Event::Learn(x, list, refs) => {
                if self.view[x] == Held::Unknown {
                    self.view[x] = Held::Known { list, refs };
                    self.queue.push(x);
                    self.queue.extend(self.listers(x));
                }
            }
            Event::Right(x, on) => {
                if on {
                    self.rights.insert(x);
                    if self.pending.contains(&x) {
                        self.queue.push(x);
                    }
                } else {
                    self.rights.remove(&x);
                }
            }
        }
    }

    /// Judges the queue; returns the things this node ends.
    pub fn settle(&mut self) -> Vec<T> {
        let mut ended = Vec::new();
        while let Some(x) = self.queue.pop() {
            if !matches!(self.view[x], Held::Known { .. }) {
                continue;
            }
            self.judged += 1;
            if walk(&self.view, x) {
                if self.rights.contains(&x) {
                    let below = self.below(x);
                    self.view[x] = Held::Ended;
                    self.pending.remove(&x);
                    ended.push(x);
                    self.queue.extend(below);
                } else if self.pending.insert(x) {
                    self.queue.extend(self.below(x));
                }
            } else if self.pending.remove(&x) {
                self.queue.extend(self.below(x));
            }
        }
        ended
    }
}
