//! World copies (tests): an exact in-memory copy of a set of nodes sharing no mutable state with
//! the original (notes/testing.md, Copied worlds). Inside `copying`, `remap` gives each shared
//! handle (`Arc`) of the original one new handle, so what two parts of the original share (a
//! device's fault plan, a store's data behind two backend handles, a memo's stamp table) the
//! copy's parts share too, and nothing of the copy points at the original.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

type Map = HashMap<usize, (Arc<dyn Any + Send + Sync>, Arc<dyn Any + Send + Sync>)>;

thread_local! {
    static WORLD: RefCell<Option<Map>> = const { RefCell::new(None) };
}

/// Runs `f`, a copy of a world: every `remap` inside it, at any depth, maps one original handle
/// to one new handle. Nested calls join the outermost copy.
pub fn copying<T>(f: impl FnOnce() -> T) -> T {
    struct Close;
    impl Drop for Close {
        fn drop(&mut self) {
            WORLD.with(|w| *w.borrow_mut() = None);
        }
    }
    if in_copy() {
        return f();
    }
    WORLD.with(|w| *w.borrow_mut() = Some(HashMap::new()));
    let _close = Close;
    f()
}

/// Whether a `copying` runs on this thread.
pub fn in_copy() -> bool {
    WORLD.with(|w| w.borrow().is_some())
}

/// The copy's handle for `old`: made by `make` from the original's value the first time this copy
/// meets it, the same one after. Outside `copying`, a new handle each call.
pub fn remap<T: Any + Send + Sync>(old: &Arc<T>, make: impl FnOnce(&T) -> T) -> Arc<T> {
    let key = Arc::as_ptr(old) as *const () as usize;
    let found = WORLD.with(|w| w.borrow().as_ref().and_then(|m| m.get(&key).map(|(_, new)| new.clone())));
    if let Some(new) = found
        && let Ok(t) = new.downcast::<T>()
    {
        return t;
    }
    let new = Arc::new(make(old));
    WORLD.with(|w| {
        if let Some(m) = w.borrow_mut().as_mut() {
            // the original is kept so its address is not reused while the copy runs
            m.insert(key, (old.clone(), new.clone()));
        }
    });
    new
}

type Kept = std::sync::Mutex<HashMap<String, Arc<std::sync::Mutex<Option<Box<dyn Any + Send>>>>>>;

/// Worlds `cached` built, by key.
static KEPT: std::sync::LazyLock<Kept> = std::sync::LazyLock::new(Default::default);

/// Tests only: `copy` of the world `build` makes, built once per process per `key` (a name for
/// the build and every parameter it takes). Callers are test setups that hand each test a copy
/// it cannot tell from a world it built itself (notes/testing.md, Copied worlds).
#[allow(clippy::panic)]
pub fn cached<W: Send + 'static>(key: &str, build: impl FnOnce() -> W, copy: impl FnOnce(&mut W) -> W) -> W {
    let slot = KEPT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(key.to_string()).or_default().clone();
    let mut slot = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut w: Box<W> = match slot.take().map(|b| b.downcast::<W>()) {
        Some(Ok(w)) => w,
        Some(Err(_)) => panic!("world {key}: one type per key"),
        None => Box::new(build()),
    };
    let out = copy(&mut w);
    *slot = Some(w);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (internal: notes/testing.md, Copied worlds). Inside one copy a shared handle
    // maps to one new handle; outside, every remap is new; the copy shares nothing with the
    // original.
    #[test]
    fn one_new_handle_per_original_handle() {
        let a = Arc::new(std::sync::Mutex::new(1));
        let (x, y) = copying(|| (remap(&a, |m| std::sync::Mutex::new(*m.lock().unwrap_or_else(|e| e.into_inner()))), remap(&a, |_| std::sync::Mutex::new(9))));
        assert!(Arc::ptr_eq(&x, &y) && !Arc::ptr_eq(&a, &x));
        assert_eq!(*x.lock().unwrap_or_else(|e| e.into_inner()), 1);
        let z = remap(&a, |_| std::sync::Mutex::new(2));
        assert!(!Arc::ptr_eq(&z, &x) && !in_copy());
    }
}
