//! Contacts and profiles (notes/std.md): a profile is contact aspects on the person's profile
//! thing, read by everyone holding its card; a contact of mine links the profile and overrides
//! it field by field; a contact without a profile is just my data. Tier 1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::scenario as common;
use common::*;
use osis::core::NAME;
use osis::{Osis, Place, Result, Tid};
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
    let profile = db.get(contact, PROFILE)?;
    let own_or = |db: &Osis, key: osis::schema::Aspect<BTreeMap<String, Labeled>>| -> Result<BTreeMap<String, Labeled>> {
        let mut m = match profile {
            Some(p) => db.get(p, key)?.unwrap_or_default(),
            None => BTreeMap::new(),
        };
        m.extend(db.get(contact, key)?.unwrap_or_default());
        Ok(m)
    };
    let name = match db.get(contact, NAME)? {
        Some(n) => Some(n),
        None => match profile {
            Some(p) => db.get(p, NAME)?,
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
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let p = alice.profile().unwrap();
    alice
        .write_with(|wr| {
            wr.at(p, NAME).set(&"Alice Example".to_string())?;
            wr.at(p, NAMES).set(&Names { given: Some("Alice".into()), family: Some("Example".into()), middle: None, prefix: None, suffix: None })?;
            wr.at(p, EMAILS).set(&BTreeMap::from([("alice@example.com".to_string(), labeled("home", true))]))
        })
        .unwrap();
    let a = introduce(&mut w, &bob, &alice);
    assert_eq!(bob.profile_of(a).unwrap(), Some(p));
    assert_eq!(bob.get(p, NAME).unwrap().as_deref(), Some("Alice Example"));
    assert_eq!(bob.get(p, NAMES).unwrap().unwrap().family.as_deref(), Some("Example"));

    // a later profile change reaches the card holder
    alice.write_with(|wr| wr.at(p, PHONES).set(&BTreeMap::from([("+49 30 1".to_string(), labeled("work", false))]))).unwrap();
    w.run();
    assert_eq!(bob.get(p, PHONES).unwrap().unwrap().len(), 1);

    // Bob's contact for Alice: linked, with his own name for her and an extra phone
    let contacts = private_tag(&bob, "Contacts").unwrap();
    let c = bob
        .write_with(|wr| {
            let c = wr.create(bob.me(), Place::In(contacts))?;
            wr.at(c, PROFILE).set(&p)?;
            wr.at(c, NAME).set(&"Al".to_string())?;
            wr.at(c, PHONES).set(&BTreeMap::from([("+1 555 0100".to_string(), labeled("mobile", true))]))?;
            Ok(c)
        })
        .unwrap();
    let v = view(&bob, c).unwrap();
    assert_eq!(v.name.as_deref(), Some("Al"), "own name overrides the profile's");
    assert_eq!(v.emails.keys().collect::<Vec<_>>(), ["alice@example.com"], "the profile's email shows through");
    assert_eq!(v.phones.len(), 2, "own phone plus the profile's");
    assert_eq!(bob.get(c, PROFILE).unwrap(), Some(p));
    assert_eq!(tag_names(&bob, c).unwrap(), ["Contacts"]);

    // a contact who is not an osis user
    let d = bob
        .write_with(|wr| {
            let d = wr.create(bob.me(), Place::In(contacts))?;
            wr.at(d, NAME).set(&"Dentist".to_string())?;
            wr.at(d, ORG).set(&Org { name: "Smile Clinic".into(), department: String::new(), title: String::new() })?;
            wr.at(d, DATES).set(&BTreeMap::from([("birthday".to_string(), Annual { month: 3, day: 14, year: None })]))?;
            Ok(d)
        })
        .unwrap();
    let v = view(&bob, d).unwrap();
    assert_eq!(v.name.as_deref(), Some("Dentist"));
    assert!(v.emails.is_empty() && v.phones.is_empty());
    assert_eq!(bob.get(d, ORG).unwrap().unwrap().name, "Smile Clinic");
    assert_eq!(bob.get(d, DATES).unwrap().unwrap()["birthday"].year, None);
}
