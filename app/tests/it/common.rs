//! What the two-node and two-account tests share: a node on a manual clock, and commits
//! delivered by hand (the engine-level path of core's tests).
use osis::internals::Internals as _;
use osis::internals::ManualClock;
use osis::{MemStore, Osis, Store};
use std::sync::Arc;

/// The app's account over a fresh in-memory node, its home made.
pub fn data() -> osis_kit::store::Data {
    let d = osis_app::store::data(osis::internals::create(osis::internals::Opening::memory()).unwrap());
    d.home().unwrap();
    d
}

/// Saves `text` in a form row, as Enter or leaving its field does.
pub fn save(d: &osis_kit::store::Data, row: &osis_kit::view::FormRow, text: &str) -> osis::Result<()> {
    row.save.as_ref().expect("an input row").run(&osis_kit::view::Act::new(d, &osis_kit::view::WindowState::default()), &osis_kit::view::Input::Text(text.into()))
}

pub fn cfg(seed: u64, clock: &Arc<ManualClock>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(seed);
    c.app.internals.clock = Some(clock.clone());
    c
}

/// Every commit `from` holds that `to` takes (another account's private commits it cannot use
/// are refused; one account's own all apply). Of another account, `to`'s account holds `from`'s first (a strong in its account
/// root, as importing a contact does), so what judges `from`'s writes stays at `to` (spec/commits.md
/// §5 What a held thing needs) and a grant to it can box it.
pub fn deliver(from: &Osis, to: &Osis) {
    let (root, who) = (to.account_root(), from.me());
    if who != to.me() && !to.holds(root, who).unwrap() {
        let mut w = to.write();
        w.hold(root, who).unwrap();
        w.commit().unwrap();
    }
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let r = to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
        assert!(r.is_ok() || who != to.me(), "{r:?}");
    }
    // a grant from outside reaches its holder as an offer, its fire (spec/sync-inbox.md §5 Grant from outside)
    osis::internals::pass_fires(from, to);
}
