//! Contacts and profiles (notes/std.md): a profile is contact aspects on the account's profile
//! thing, read by everyone holding its card; a contact of mine links the profile and overrides
//! it field by field; a contact without a profile is just my data. Tier 1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use crate::scenario as common;
use common::*;
use crate::common::CreateIn;
use osis::core::NAME;
use osis::{Osis, Result, Tid};
use osis_sim::world::World;
use crate::schemas::contact::*;
use std::collections::BTreeMap;

fn labeled(label: &str, pref: bool) -> Labeled {
    Labeled { label: label.into(), pref }
}

/// What a contacts app shows for a contact: its own values, else the linked profile's.
struct View {
    name: Option<String>,
    emails: BTreeMap<String, Labeled>,
    phones: BTreeMap<String, Labeled>,
}

fn view(db: &Osis, contact: Tid) -> Result<View> {
    let profile = db.at(contact, PROFILE).get()?;
    let own_or = |db: &Osis, key: osis::internals::schema::Aspect<BTreeMap<String, Labeled>>| -> Result<BTreeMap<String, Labeled>> {
        let mut m = match profile {
            Some(p) => db.at(p, key).get()?.unwrap_or_default(),
            None => BTreeMap::new(),
        };
        m.extend(db.at(contact, key).get()?.unwrap_or_default());
        Ok(m)
    };
    let name = match db.at(contact, NAME).get()? {
        Some(n) => Some(n),
        None => match profile {
            Some(p) => db.at(p, NAME).get()?,
            None => None,
        },
    };
    Ok(View { name, emails: own_or(db, EMAILS)?, phones: own_or(db, PHONES)? })
}

// spec/sync.md §3 (contact card: a read link to the profile), notes/std.md (profile and
// contact): Alice fills her profile; Bob imports her card, reads the profile, and keeps reading
// it as she changes it. His contact for her links the profile, overrides her name and adds a
// phone; a contact without a profile holds only his data.
#[test]
fn profile_and_contact_overlay() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = account(&mut w, 1, host);
    let bob = account(&mut w, 2, host);
    let p = alice.profile().unwrap();
    let mut wr = alice.write();
    wr.at(p, NAME).set(&"Alice Example".to_string()).unwrap();
    wr.at(p, NAMES).set(&Names { given: Some("Alice".into()), family: Some("Example".into()), middle: None, prefix: None, suffix: None }).unwrap();
    wr.at(p, EMAILS).set(&BTreeMap::from([("alice@example.com".to_string(), labeled("home", true))])).unwrap();
    wr.commit().unwrap();
    let a = introduce(&mut w, &bob, &alice);
    assert_eq!(bob.profile_of(a).unwrap(), Some(p));
    assert_eq!(bob.at(p, NAME).get().unwrap().as_deref(), Some("Alice Example"));
    assert_eq!(bob.at(p, NAMES).get().unwrap().unwrap().family.as_deref(), Some("Example"));

    // a later profile change reaches the card holder
    alice.commit_set(p, PHONES, &BTreeMap::from([("+49 30 1".to_string(), labeled("work", false))])).unwrap();
    w.run();
    assert_eq!(bob.at(p, PHONES).get().unwrap().unwrap().len(), 1);

    // Bob's contact for Alice: linked, with his own name for her and an extra phone
    let contacts = private_tag(&bob, "Contacts").unwrap();
    let mut wr = bob.write();
    let c = wr.create_in(bob.me(), &[contacts]).unwrap();
    wr.at(c, PROFILE).set(&p).unwrap();
    wr.at(c, NAME).set(&"Al".to_string()).unwrap();
    wr.at(c, PHONES).set(&BTreeMap::from([("+1 555 0100".to_string(), labeled("mobile", true))])).unwrap();
    wr.commit().unwrap();
    let v = view(&bob, c).unwrap();
    assert_eq!(v.name.as_deref(), Some("Al"), "own name overrides the profile's");
    assert_eq!(v.emails.keys().collect::<Vec<_>>(), ["alice@example.com"], "the profile's email shows through");
    assert_eq!(v.phones.len(), 2, "own phone plus the profile's");
    assert_eq!(bob.at(c, PROFILE).get().unwrap(), Some(p));
    assert_eq!(tag_names(&bob, c).unwrap(), ["Contacts"]);

    // a contact who is not an osis user
    let mut wr = bob.write();
    let d = wr.create_in(bob.me(), &[contacts]).unwrap();
    wr.at(d, NAME).set(&"Dentist".to_string()).unwrap();
    wr.at(d, ORG).set(&Org { name: "Smile Clinic".into(), department: String::new(), title: String::new() }).unwrap();
    wr.at(d, DATES).set(&BTreeMap::from([("birthday".to_string(), Annual { month: 3, day: 14, year: None })])).unwrap();
    wr.commit().unwrap();
    let v = view(&bob, d).unwrap();
    assert_eq!(v.name.as_deref(), Some("Dentist"));
    assert!(v.emails.is_empty() && v.phones.is_empty());
    assert_eq!(bob.at(d, ORG).get().unwrap().unwrap().name, "Smile Clinic");
    assert_eq!(bob.at(d, DATES).get().unwrap().unwrap()["birthday"].year, None);
}

/// spec/sync.md §3: a contact card needs peers; on a peerless node `contact_card` and
/// `profile` fail before writing anything, so each try leaves no commit or thing behind.
#[test]
fn contact_card_without_peers_writes_nothing() {
    let db = crate::common::db(7);
    let all = osis::CommitQuery::default();
    let before = db.commits(&all).unwrap().len();
    for _ in 0..2 {
        assert!(matches!(db.contact_card(), Err(osis::Error::Invalid(_))));
        assert!(db.profile().is_err());
    }
    assert_eq!(db.commits(&all).unwrap().len(), before);
}
