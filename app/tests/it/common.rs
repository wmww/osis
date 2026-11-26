//! What the two-node and two-account tests share: a node on a manual clock, and commits
//! delivered by hand (the engine-level path of core's tests).
use osis::internals::Internals as _;
use osis::internals::ManualClock;
use osis::{MemStore, Osis, Store};
use std::sync::Arc;

/// A new node in `o` with an account of its own (osis-account), as the app makes one.
pub fn created(o: osis::internals::Opening) -> Osis {
    let db = osis::internals::create(o).unwrap();
    osis_account::Account::make(&db).unwrap();
    db
}

/// The app's account over a fresh in-memory node, its home seeded.
pub fn data() -> osis_kit::store::Data {
    osis_app::store::data(created(osis::internals::Opening::memory())).unwrap()
}

/// The account `db` acts for: the person, and home.
pub fn account(db: &Osis) -> osis::Result<osis::Tid> {
    Ok(osis_account::Account::of(db)?.ok_or_else(|| osis::Error::Invalid("this node acts for no account".into()))?.thing())
}

/// Saves `text` in a form row, as Enter or leaving its field does.
pub fn save(d: &osis_kit::store::Data, row: &osis_kit::view::FormRow, text: &str) -> osis::Result<()> {
    row.save.as_ref().expect("an input row").run(&osis_kit::view::Act::new(d, &osis_kit::view::WindowState::default()), &osis_kit::view::Input::Text(text.into()))
}

/// The clock a test's nodes share, at a fixed start.
pub fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(osis::Time(1_760_000_000_000)))
}

/// A fresh in-memory node of its own account, seeded `seed`, on `clock`.
pub fn node(seed: u64, clock: &Arc<ManualClock>) -> Osis {
    created(cfg(seed, clock))
}

pub fn cfg(seed: u64, clock: &Arc<ManualClock>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(seed);
    c.app.internals.clock = Some(clock.clone());
    c
}

/// `deliver` both ways, twice: what either answers to the other's commits arrives too.
pub fn sync(a: &Osis, b: &Osis) {
    for _ in 0..2 {
        deliver(a, b);
        deliver(b, a);
    }
}

/// Every commit `from` holds that `to` takes (another account's private commits it cannot use
/// are refused; one account's own all apply). Of another account, `to`'s account holds `from`'s
/// account and its profile first (strongs from its `holds.0`, as importing its contact card
/// would): what judges `from`'s writes stays at `to` (spec/commits.md §5 What a held thing
/// needs), and the profile's card gives the account's keys and inbox, so a grant to it boxes it
/// and fires at that inbox.
pub fn deliver(from: &Osis, to: &Osis) {
    let account = |d: &Osis| osis_account::Account::of(d).unwrap().unwrap();
    let (root, who) = (account(to), account(from));
    let other = who != root;
    if other {
        let profile = who.realm().profile(from).unwrap().unwrap();
        for t in [who.thing(), profile] {
            if !to.holds(root.thing(), t).unwrap() {
                let mut w = to.write();
                w.hold(root.thing(), t).unwrap();
                w.commit().unwrap();
            }
        }
    }
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let r = to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
        assert!(r.is_ok() || other, "{r:?}");
    }
    // a grant from outside reaches its holder as an offer, its fire (spec/sync-inbox.md §5 Grant from outside)
    osis::internals::pass_fires(from, to);
}
