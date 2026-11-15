//! A persistent set of small integers (a treap whose shape is a function of its keys alone:
//! each key's priority is a fixed mix of it). A set made from another by a few inserts shares
//! every subtree they do not touch, so a set per rotation along a chain costs O(log n) each, and
//! the union of two sets made from one costs about their difference, not their size.

use std::sync::Arc;

#[derive(Clone, Default)]
pub(crate) struct PSet(Option<Arc<Node>>);

struct Node {
    key: u32,
    left: PSet,
    right: PSet,
}

/// The key's priority: a bijective mix, so no two keys tie.
fn prio(k: u32) -> u64 {
    let mut z = u64::from(k).wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn node(key: u32, left: PSet, right: PSet) -> PSet {
    PSet(Some(Arc::new(Node { key, left, right })))
}

impl PSet {
    pub(crate) fn new() -> PSet {
        PSet(None)
    }

    pub(crate) fn contains(&self, k: u32) -> bool {
        let mut t = &self.0;
        while let Some(n) = t {
            t = match k.cmp(&n.key) {
                std::cmp::Ordering::Less => &n.left.0,
                std::cmp::Ordering::Greater => &n.right.0,
                std::cmp::Ordering::Equal => return true,
            };
        }
        false
    }

    /// The keys below `k` and those above it (`k` itself dropped).
    fn split(&self, k: u32) -> (PSet, PSet) {
        let Some(n) = &self.0 else { return (PSet(None), PSet(None)) };
        match k.cmp(&n.key) {
            std::cmp::Ordering::Equal => (n.left.clone(), n.right.clone()),
            std::cmp::Ordering::Less => {
                let (l, r) = n.left.split(k);
                (l, node(n.key, r, n.right.clone()))
            }
            std::cmp::Ordering::Greater => {
                let (l, r) = n.right.split(k);
                (node(n.key, n.left.clone(), l), r)
            }
        }
    }

    pub(crate) fn insert(&self, k: u32) -> PSet {
        if self.contains(k) {
            return self.clone();
        }
        self.union(&node(k, PSet(None), PSet(None)))
    }

    pub(crate) fn remove(&self, k: u32) -> PSet {
        if !self.contains(k) {
            return self.clone();
        }
        let (l, r) = self.split(k);
        l.union(&r)
    }

    /// The union: subtrees the two share are taken whole.
    pub(crate) fn union(&self, other: &PSet) -> PSet {
        let (a, b) = match (&self.0, &other.0) {
            (None, _) => return other.clone(),
            (_, None) => return self.clone(),
            (Some(a), Some(b)) if Arc::ptr_eq(a, b) => return self.clone(),
            (Some(a), Some(b)) => (a, b),
        };
        let (top, rest) = if prio(a.key) >= prio(b.key) { (a, other) } else { (b, self) };
        let (l, r) = rest.split(top.key);
        node(top.key, top.left.union(&l), top.right.union(&r))
    }

    /// The keys, ascending.
    pub(crate) fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let mut stack: Vec<&Node> = Vec::new();
        let mut cur = self.0.as_deref();
        std::iter::from_fn(move || {
            while let Some(n) = cur {
                stack.push(n);
                cur = n.left.0.as_deref();
            }
            let n = stack.pop()?;
            cur = n.right.0.as_deref();
            Some(n.key)
        })
    }
}

impl PartialEq for PSet {
    fn eq(&self, other: &PSet) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for PSet {}

impl std::fmt::Debug for PSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}
