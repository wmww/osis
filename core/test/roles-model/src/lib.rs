//! Reference models of the role rules, independent of any osis crate: oracles for osis-perm,
//! osis-engine and held-model, never patched to match the implementation. Modules:
//! - `paths`: the role timeline, content validity and purge rights along stated paths
//!   (spec/permissions.md §1 Path, §2, §5.1, §5.2, §6), the stolen-node story over them and the
//!   purge worlds (README.md, Paths; findings in notes/path-model-findings.md). osis-perm's
//!   `paths::` differentials and held-model's judgment read it. Searches `paths`, `paths-exh`,
//!   `paths-tiny*`, `paths-purge`.
//! - `paths::proofs`: connection proofs by claimed path (spec/sync-opens.md §2, §4 J). Searches
//!   `proofs`, `proofs-exh`.
//! - `leave`: the own self-removal exception of Encrypting under (spec/crypto.md §4) and held
//!   elsewhere for a self-removal (spec/sync-status.md §2). Searches `leave`, `leave-exh`.
//! - `told`: a removed node learns its removal from any member, a blind remover's included, and
//!   gains nothing else; a reader lowered to sync opens no later removal's notice
//!   (spec/sync-opens.md §4 Departed, §6; spec/permissions.md §4 Notices). Searches
//!   `told`, `told-exh`.
//! - `shrink`: `without`, a move list less one move.
//! Binary: `cargo run --bin roles-model -- [samples] [mode]`; `cargo test` runs the hand worlds.

pub mod idset;
pub mod leave;
pub mod paths;
pub mod shrink;
pub mod told;

/// Roles, `None` below read. The build's sync role (below read) is not modelled: §5.1 judges it as
/// read (neither writes nor audits).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Role {
    None,
    Read,
    Write,
    Admin,
}

/// Counters a search sums over threads.
pub trait Tally: Default + Send {
    fn merge(&mut self, o: Self);
}

impl Tally for u64 {
    fn merge(&mut self, o: u64) {
        *self += o;
    }
}

impl<const N: usize> Tally for [u64; N]
where
    [u64; N]: Default,
{
    fn merge(&mut self, o: Self) {
        for (a, b) in self.iter_mut().zip(o) {
            *a += b;
        }
    }
}

impl<K: Ord + Send> Tally for std::collections::BTreeMap<K, u64> {
    fn merge(&mut self, o: Self) {
        for (k, n) in o {
            *self.entry(k).or_default() += n;
        }
    }
}

/// A search's tally: failing checks by kind (a message's text before its first ':'), the
/// first world failing each of up to four kinds, and named counts.
#[derive(Debug)]
pub struct Findings<W> {
    pub worlds: u64,
    pub failures: u64,
    pub kinds: std::collections::BTreeMap<String, u64>,
    pub fail: Vec<(String, W)>,
    pub counts: std::collections::BTreeMap<&'static str, u64>,
}

impl<W> Default for Findings<W> {
    fn default() -> Self {
        Findings { worlds: 0, failures: 0, kinds: Default::default(), fail: vec![], counts: Default::default() }
    }
}

impl<W: Send> Tally for Findings<W> {
    fn merge(&mut self, o: Self) {
        self.worlds += o.worlds;
        self.failures += o.failures;
        Tally::merge(&mut self.kinds, o.kinds);
        Tally::merge(&mut self.counts, o.counts);
        let room = 4usize.saturating_sub(self.fail.len());
        self.fail.extend(o.fail.into_iter().take(room));
    }
}

impl<W: Clone> Findings<W> {
    pub fn count(&mut self, k: &'static str, n: u64) {
        *self.counts.entry(k).or_default() += n;
    }
    pub fn get(&self, k: &str) -> u64 {
        self.counts.get(k).copied().unwrap_or(0)
    }
    /// Each of `fails` (messages `kind: what`) found in world `w`.
    pub fn failed(&mut self, fails: Vec<String>, w: &W) {
        for f in fails {
            self.failures += 1;
            let n = self.kinds.entry(f.split(':').next().unwrap_or("").to_string()).or_default();
            *n += 1;
            if *n == 1 && self.fail.len() < 4 {
                self.fail.push((f, w.clone()));
            }
        }
    }
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds, {} failing checks", self.worlds, self.failures);
        for (k, n) in &self.kinds {
            println!("  {k}: {n}");
        }
        println!("  counted: {}", self.counts.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", "));
    }
}

impl<A: Tally, B: Tally> Tally for (A, B) {
    fn merge(&mut self, o: Self) {
        self.0.merge(o.0);
        self.1.merge(o.1);
    }
}

/// `f(thread, threads, tally)` on a thread per core, the tallies summed.
pub fn on_every_core<T: Tally>(f: impl Fn(usize, usize, &mut T) + Sync) -> T {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut t = T::default();
                    f(th, threads, &mut t);
                    t
                })
            })
            .collect();
        hs.into_iter().fold(T::default(), |mut all, h| {
            all.merge(h.join().unwrap());
            all
        })
    })
}

/// Why every `stride`th world of a family of `total` cannot stand for the family: none when it can.
/// A family's world index is mixed-radix over its dimensions, `total` their product; the worlds
/// `0, s, 2s, ...` reach every value of every dimension only when `s` shares no factor with any,
/// i.e. with `total` (an even stride over a first dimension of 2 holds it at 0 in every world).
pub fn stride_refusal(stride: usize, total: usize) -> Option<String> {
    let gcd = |mut a: usize, mut b: usize| {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    };
    match gcd(stride, total) {
        _ if stride == 0 => Some("stride 0: give at least 1 (1 runs every world)".into()),
        1 => None,
        g => Some(format!(
            "stride {stride} shares the factor {g} with the family's size {total} (the product of its dimensions): \
             a dimension that factor divides would be sampled at some of its values only; pick a stride coprime to {total} (a prime not dividing it)"
        )),
    }
}

/// `f(world, tally)` for every `stride`th world of `0..total` (a family: `stride_refusal`) on a
/// thread per core. Panics on a stride `stride_refusal` refuses.
pub fn family_on_every_core<T: Tally>(total: usize, stride: usize, f: impl Fn(usize, &mut T) + Sync) -> T {
    if let Some(why) = stride_refusal(stride, total) {
        panic!("{why}");
    }
    on_every_core(|th, threads, t| {
        for i in (th * stride..total).step_by(threads * stride) {
            f(i, t);
        }
    })
}

/// A test's decimal `u64` environment variable (unset or empty: None).
#[cfg(test)]
pub(crate) fn env_u64(k: &str) -> Option<u64> {
    std::env::var(k).ok().filter(|v| !v.is_empty()).map(|v| v.parse::<u64>().unwrap_or_else(|_| panic!("{k}={v:?} is not a decimal u64")))
}

#[cfg(test)]
mod stride_tests {
    use super::*;

    // spec: none (the search runner)
    #[test]
    fn a_stride_sharing_a_factor_with_the_family_is_refused() {
        // dimensions 2 and 3: stride 2 holds the first at 0, stride 3 the second at two values
        for bad in [0, 2, 3, 4, 6, 9] {
            assert!(stride_refusal(bad, 6).is_some(), "{bad}");
        }
        for good in [1, 5, 7, 11] {
            assert_eq!(stride_refusal(good, 6), None, "{good}");
        }
        // every 5th world of 0..42, each once, whatever the core count
        let seen = family_on_every_core(42, 5, |i, t: &mut [u64; 2]| {
            t[0] += 1;
            t[1] += i as u64;
        });
        assert_eq!(seen, [9, (0..42).step_by(5).sum::<usize>() as u64]);
        assert!(std::panic::catch_unwind(|| family_on_every_core(12, 4, |_, _: &mut [u64; 1]| ())).is_err());
    }
}

/// `f(rng, tally)` for each world `i` of `worlds` on a thread per core, world `i` drawn from its own
/// generator `Rng::thread(seed, i)`: the worlds are a function of `seed` and `worlds` alone, whatever
/// the core count.
pub fn each_world<T: Tally>(seed: u64, worlds: std::ops::Range<u64>, f: impl Fn(&mut Rng, &mut T) + Sync) -> T {
    on_every_core(|th, threads, t| {
        for i in (worlds.start + th as u64..worlds.end).step_by(threads) {
            f(&mut Rng::thread(seed, i as usize), t);
        }
    })
}

/// Seeded xorshift generator: every history is a seed (0 included).
pub struct Rng(pub u64);
impl Rng {
    /// Generator `th` (a thread's, or a world's: `each_world`) of a search seeded `seed`.
    pub fn thread(seed: u64, th: usize) -> Rng {
        Rng(seed ^ (th as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }
    pub fn next(&mut self) -> u64 {
        // (xorshift never leaves a zero state, nor reaches one)
        if self.0 == 0 {
            self.0 = 0x9E37_79B9_7F4A_7C15;
        }
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn perm(&mut self, n: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            v.swap(i, self.below(i + 1));
        }
        v
    }
}
