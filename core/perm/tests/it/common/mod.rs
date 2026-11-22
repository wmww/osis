//! Shared helpers of the osis-perm tests: seeds, shards, arrival orders.

/// A random run's seed: `seed`, or `seed` xor `OSIS_PERM_SEED` (decimal) to sample other
/// histories (`OSIS_PERM_SEED=1 cargo test -p osis-perm -- --ignored`).
pub fn seeded(seed: u64) -> u64 {
    osis_base::testenv::u64_var("OSIS_PERM_SEED").map_or(seed, |v| seed ^ v)
}

/// Property runs are split into this many shards, each with its own seed (`shard_seed`);
/// fixed, so a failure's seed is the same on every machine.
pub const SHARDS: u64 = 16;

/// The seed of shard `i` of a run seeded `seed` (before `seeded`).
pub fn shard_seed(seed: u64, i: u64) -> u64 {
    seed ^ (i << 40)
}

/// Runs `run(samples, seed)` as `SHARDS` shards of `samples / SHARDS` (at least one) on
/// scoped threads, each running once it holds a permit (`osis_base::testenv::Permit`: concurrent
/// tests share the cores), shard i seeded
/// `shard_seed(seed, i)`; returns their results in shard order. A panicking shard panics the
/// run (its message is printed by the shard's thread).
pub fn sharded<T: Send>(samples: u64, seed: u64, run: impl Fn(u64, u64) -> T + Sync) -> Vec<T> {
    let per = (osis_base::testenv::large_n(samples) / SHARDS).max(1);
    let run = &run;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..SHARDS)
            .map(|i| {
                s.spawn(move || {
                    let _p = osis_base::testenv::Permit::take();
                    run(per, shard_seed(seed, i))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| panic!("a shard of seed {seed:#x} failed (message above)"))).collect()
    })
}

/// Every arrival order of items `0..n`, prefixes shared: `step(state, order, k)` adds item `k`
/// after `order` (once per distinct prefix), `end(state, order)` reads each whole order.
pub fn every_order<S: Clone>(n: usize, start: S, step: &mut impl FnMut(&mut S, &[usize], usize), end: &mut impl FnMut(&mut S, &[usize])) {
    fn go<S: Clone>(s: &S, order: &mut Vec<usize>, n: usize, step: &mut impl FnMut(&mut S, &[usize], usize), end: &mut impl FnMut(&mut S, &[usize])) {
        if order.len() == n {
            end(&mut s.clone(), order);
        }
        for k in 0..n {
            if order.contains(&k) {
                continue;
            }
            let mut t = s.clone();
            step(&mut t, order, k);
            order.push(k);
            go(&t, order, n, step, end);
            order.pop();
        }
    }
    go(&start, &mut vec![], n, step, end);
}
