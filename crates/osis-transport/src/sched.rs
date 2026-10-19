//! `Sched`: a single-threaded executor that polls ready tasks in a seeded order and steps a
//! `Net` when every task is blocked. Same seed, same interleaving: tier-1 tests of drivers and
//! streams run without tokio, threads or sleeps.

use crate::mem::Net;
use crate::util::{lock, Rng};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};

type Task = Pin<Box<dyn Future<Output = ()>>>;

struct Shared {
    ready: Arc<Mutex<BTreeSet<u64>>>,
    spawned: RefCell<Vec<(u64, Task)>>,
    next: Cell<u64>,
}

struct TaskWaker {
    id: u64,
    ready: Arc<Mutex<BTreeSet<u64>>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        lock(&self.ready).insert(self.id);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        lock(&self.ready).insert(self.id);
    }
}

/// Spawns onto the `Sched` it came from, also from inside a task.
#[derive(Clone)]
pub struct Spawner(Rc<Shared>);

impl Spawner {
    pub fn spawn(&self, f: impl Future<Output = ()> + 'static) {
        let id = self.0.next.get();
        self.0.next.set(id.wrapping_add(1));
        self.0.spawned.borrow_mut().push((id, Box::pin(f)));
        lock(&self.0.ready).insert(id);
    }
}

pub struct Sched {
    rng: Rng,
    net: Option<Net>,
    tasks: BTreeMap<u64, Task>,
    shared: Rc<Shared>,
    max_steps: u64,
    capped: bool,
}

impl Sched {
    /// `net`, if any, is stepped whenever no task is ready.
    pub fn new(seed: u64, net: Option<Net>) -> Sched {
        Sched {
            rng: Rng::new(seed),
            net,
            tasks: BTreeMap::new(),
            shared: Rc::new(Shared { ready: Arc::new(Mutex::new(BTreeSet::new())), spawned: RefCell::new(Vec::new()), next: Cell::new(0) }),
            max_steps: 1_000_000,
            capped: false,
        }
    }

    /// Bounds the virtual steps one `run` may take (default one million).
    pub fn set_max_steps(&mut self, n: u64) {
        self.max_steps = n;
    }

    pub fn spawner(&self) -> Spawner {
        Spawner(self.shared.clone())
    }

    pub fn spawn(&self, f: impl Future<Output = ()> + 'static) {
        self.spawner().spawn(f)
    }

    /// Whether the last `run` stopped at the step cap rather than with every task blocked.
    pub fn capped(&self) -> bool {
        self.capped
    }

    /// Runs until no task is ready and the net has nothing pending (or the step cap); returns
    /// the tasks still blocked. Idle stretches with only timers pending are skipped.
    pub fn run(&mut self) -> usize {
        let mut steps = 0u64;
        self.capped = false;
        loop {
            self.tasks.extend(self.shared.spawned.borrow_mut().drain(..));
            let pick = {
                let mut ready = lock(&self.shared.ready);
                let n = ready.len() as u64;
                let k = self.rng.below(n);
                let id = ready.iter().nth(k as usize).copied();
                if let Some(id) = id {
                    ready.remove(&id);
                }
                id
            };
            let Some(id) = pick else {
                match &self.net {
                    Some(net) if net.pending() => {
                        if steps >= self.max_steps {
                            self.capped = true;
                            return self.tasks.len();
                        }
                        net.skip_idle();
                        net.step();
                        steps += 1;
                        continue;
                    }
                    _ => return self.tasks.len(),
                }
            };
            let Some(mut t) = self.tasks.remove(&id) else { continue };
            let w = Waker::from(Arc::new(TaskWaker { id, ready: self.shared.ready.clone() }));
            if t.as_mut().poll(&mut Context::from_waker(&w)).is_pending() {
                self.tasks.insert(id, t);
            }
        }
    }

    /// Runs `f` with everything else spawned; `None` if it was still blocked when the run ended.
    pub fn block_on<T: 'static>(&mut self, f: impl Future<Output = T> + 'static) -> Option<T> {
        let out = Rc::new(RefCell::new(None));
        let o = out.clone();
        self.spawn(async move {
            let v = f.await;
            *o.borrow_mut() = Some(v);
        });
        self.run();
        out.borrow_mut().take()
    }
}
