//! Tags (notes/tags.md): sharing a tag per item through one roster, sub-tags, only what you may
//! share, tag-owned things, ownership transfer. Tier 1 (the slower cases tier 2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;
use common::*;
use osis::core::{BODY, GROUP, NAME, TAG, Tag};
use osis::{Demotion, EdgeOpts, Error, Lower, Osis, Place, Result, Role, Tid};
use osis_sim::world::World;

/// A sub-tag of `parent` owned by `owner`, with an edge for the parent (unless the parent owns it)
/// so the parent's members reach what it holds.
fn new_sub_tag(db: &Osis, owner: Tid, parent: Tid, name: &str, role: Role) -> Result<Tid> {
    let t = db.write_with(|w| {
        let t = w.create(owner, Place::In(parent))?;
        w.make_group(t)?;
        w.at(t, TAG).set(&Tag::default())?;
        w.at(t, NAME).set(&name.to_string())?;
        w.add_subgroup(parent, t)?;
        Ok(t)
    })?;
    if owner != parent {
        db.grant(t, parent, role, EdgeOpts::default())?;
    }
    Ok(t)
}

/// A card: a thing with a body, owned by `owner`, placed nowhere yet.
fn new_card(db: &Osis, owner: Tid, text: &str) -> Result<Tid> {
    db.write_with(|w| {
        let c = w.create(owner, Place::Unsynced)?;
        w.at(c, BODY).set(&text.to_string())?;
        Ok(c)
    })
}

/// Adds a thing the person owns to a tag: a placement plus an edge for the tag's actor, so the
/// tag's members reach it (capped by their role on the tag) and it syncs under the tag's label
/// (spec/sync.md §3, entitlement). Placing alone shares nothing.
fn add(db: &Osis, tag: Tid, thing: Tid, role: Role) -> Result<()> {
    db.write_with(|w| w.place(thing, tag))?;
    db.grant(thing, tag, role, EdgeOpts::default())
}

fn place(db: &Osis, tag: Tid, thing: Tid) -> Result<()> {
    db.write_with(|w| w.place(thing, tag))
}

/// Removes a thing from a tag and ends the tag's edge on it (the thing's secrets rotate).
async fn remove(db: &Osis, tag: Tid, thing: Tid) -> Result<()> {
    db.write_with(|w| w.unplace(thing, tag))?;
    db.demote(thing, tag, Lower::Remove, Demotion::default()).await
}

fn edit(db: &Osis, card: Tid, shown: &str, new: &str) -> Result<()> {
    db.write_with(|w| w.at(card, BODY).edit(&shown.to_string(), &new.to_string()))
}

fn text(db: &Osis, card: Tid) -> Result<Option<String>> {
    db.get(card, BODY)
}

/// The things in a tag and its sub-tags (subgroups carrying `/tag`).
fn list(db: &Osis, tag: Tid) -> Result<(Vec<Tid>, Vec<Tid>)> {
    let g = db.get(tag, GROUP)?.unwrap_or_default();
    let things = g.items.iter().filter(|t| !g.subgroups.contains(t)).copied().collect();
    let mut subs = Vec::new();
    for s in g.subgroups {
        if db.get(s, TAG)?.is_some() {
            subs.push(s);
        }
    }
    Ok((things, subs))
}

fn share(db: &Osis, tag: Tid, person: Tid, role: Role, invite: Option<Role>) -> Result<()> {
    db.grant(tag, person, role, EdgeOpts { until: None, invite })
}

// notes/tags.md (sharing a tag per item through one roster), spec/sync.md §3 (entitlement),
// spec/requirements.md (Permissions: grouping grants no rights): Alice's cards stay hers; each
// one in the shared tag has an edge for the tag. Bob reads them (one added after he joined too),
// capped by his role on the tag; a card only placed is not shared; a card removed from the tag
// shows him nothing new.
#[test]
fn shared_tag_per_item() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let b = introduce(&mut w, &alice, &bob);
    let trip = new_tag(&alice, "Trip").unwrap();
    let plan = new_card(&alice, alice.me(), "flights").unwrap();
    add(&alice, trip, plan, Role::Write).unwrap();
    let diary = new_card(&alice, alice.me(), "private").unwrap();
    place(&alice, trip, diary).unwrap();
    share(&alice, trip, b, Role::Read, None).unwrap();
    w.run();
    assert_eq!(text(&bob, plan).unwrap().as_deref(), Some("flights"));
    assert_eq!(bob.role_on(plan), Some(Role::Read), "capped by the role on the tag");
    assert!(matches!(edit(&bob, plan, "flights", "x"), Err(Error::Permission { .. })));
    assert_eq!(text(&bob, diary).unwrap(), None, "placed without an edge: not shared");
    assert_eq!(list(&bob, trip).unwrap().0.len(), 2, "the placement itself is visible");

    let packing = new_card(&alice, alice.me(), "socks").unwrap();
    add(&alice, trip, packing, Role::Write).unwrap();
    w.run();
    assert_eq!(text(&bob, packing).unwrap().as_deref(), Some("socks"));
    assert_eq!(tag_names(&bob, packing).unwrap(), ["Trip"]);

    w.until(remove(&alice, trip, packing), 1000, 20).expect("pre-sync").unwrap();
    edit(&alice, packing, "socks", "socks, hat").unwrap();
    w.run();
    assert_eq!(text(&bob, packing).unwrap().as_deref(), Some("socks"), "removed from the tag: nothing new");
    assert!(tag_names(&bob, packing).unwrap().is_empty());
}

// notes/tags.md (rosters nest; only what you may share), spec/permissions.md §1 (effective role
// is the minimum along a path of edges): a member of the tag reaches a sub-tag's card through
// tag → sub-tag → card; a card someone shared with Alice read-only, placed in her tag, cannot be
// given an edge for the tag and so is not shared on.
#[test]
fn sub_tags_chain_rosters_and_only_what_you_may_share() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let carol = person(&mut w, 3, sv);
    let b = introduce(&mut w, &alice, &bob);
    let a = introduce(&mut w, &carol, &alice);
    let work = new_tag(&alice, "Work").unwrap();
    let ideas = new_sub_tag(&alice, alice.me(), work, "Ideas", Role::Read).unwrap();
    let pitch = new_card(&alice, alice.me(), "pitch").unwrap();
    add(&alice, ideas, pitch, Role::Write).unwrap();
    share(&alice, work, b, Role::Write, None).unwrap();
    let memo = new_card(&carol, carol.me(), "carol's memo").unwrap();
    carol.sync(memo, &[]).unwrap();
    carol.grant(memo, a, Role::Read, EdgeOpts::default()).unwrap();
    w.run();
    assert_eq!(text(&alice, memo).unwrap().as_deref(), Some("carol's memo"));
    place(&alice, work, memo).unwrap();
    assert!(matches!(alice.grant(memo, work, Role::Read, EdgeOpts::default()), Err(Error::Permission { .. })), "no admin on Carol's card");
    w.run();

    assert_eq!(list(&bob, work).unwrap().1, vec![ideas], "the sub-tag is a tag");
    assert_eq!(text(&bob, pitch).unwrap().as_deref(), Some("pitch"), "reached through the sub-tag");
    assert_eq!(bob.role_on(pitch), Some(Role::Read), "min(write on Work, read edge on Ideas, write edge on pitch)");
    assert!(matches!(edit(&bob, pitch, "pitch", "x"), Err(Error::Permission { .. })));
    assert_eq!(text(&bob, memo).unwrap(), None, "Carol's card is not shared on");
}

// spec/permissions.md §2 (roles), §3, §5 (demotion), notes/tags.md (writers may create
// tag-owned things): a reader reads and cannot write; a writer adds a tag-owned card; a demoted
// writer writes no more and what it wrote stays.
#[test]
#[ignore = "tier 2"]
fn tag_owned_cards_reader_writer_demotion() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let [reader, writer] = [2, 3].map(|s| person(&mut w, s, sv));
    let team = new_tag(&alice, "Team").unwrap();
    let docs = new_sub_tag(&alice, team, team, "docs", Role::Write).unwrap();
    let spec = new_card(&alice, team, "v1").unwrap();
    place(&alice, docs, spec).unwrap();
    let r = introduce(&mut w, &alice, &reader);
    let wr = introduce(&mut w, &alice, &writer);
    share(&alice, team, r, Role::Read, None).unwrap();
    share(&alice, team, wr, Role::Write, None).unwrap();
    w.run();

    assert_eq!(text(&reader, spec).unwrap().as_deref(), Some("v1"), "tag-owned things need no edge");
    assert_eq!(list(&reader, team).unwrap().1, vec![docs]);
    assert!(matches!(edit(&reader, spec, "v1", "hacked"), Err(Error::Permission { .. })));
    assert!(matches!(new_card(&reader, team, "y"), Err(Error::Permission { .. })));

    let notes = new_card(&writer, team, "from the writer").unwrap();
    place(&writer, docs, notes).unwrap();
    edit(&writer, spec, "v1", "v2").unwrap();
    w.run();
    assert_eq!(text(&alice, notes).unwrap().as_deref(), Some("from the writer"));
    assert_eq!(text(&reader, spec).unwrap().as_deref(), Some("v2"));

    w.until(alice.demote(team, wr, Lower::To(Role::Read), Demotion::default()), 1000, 20).expect("pre-sync").unwrap();
    w.run();
    assert_eq!(writer.role_on(team), Some(Role::Read));
    assert!(matches!(edit(&writer, spec, "v2", "v3"), Err(Error::Permission { .. })));
    assert_eq!(text(&reader, notes).unwrap().as_deref(), Some("from the writer"), "earlier writes stay");
}

// spec/permissions.md §2 (invite grants: up to the invite role): an invite holder shares the tag
// on, not above its invite role.
#[test]
#[ignore = "tier 2"]
fn invite_holder_shares_on() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let [inviter, guest] = [4, 5].map(|s| person(&mut w, s, sv));
    let team = new_tag(&alice, "Team").unwrap();
    let spec = new_card(&alice, team, "v1").unwrap();
    place(&alice, team, spec).unwrap();
    let iv = introduce(&mut w, &alice, &inviter);
    share(&alice, team, iv, Role::Read, Some(Role::Read)).unwrap();
    w.run();
    let g = introduce(&mut w, &inviter, &guest);
    assert!(matches!(share(&inviter, team, g, Role::Write, None), Err(Error::Permission { .. })), "invite only up to read");
    share(&inviter, team, g, Role::Read, None).unwrap();
    w.run();
    assert_eq!(text(&guest, spec).unwrap().as_deref(), Some("v1"));
    assert_eq!(alice.roster(team).get(&g).map(|e| e.role), Some(Role::Read));
}

// spec/permissions.md §7 (moving is a copy with imported history), notes/tags.md (the only copy
// is an ownership transfer): the copy has a new tid and owner, the tag keeps the original, and
// the tag's members do not read the copy.
#[test]
fn ownership_transfer_is_a_copy() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let team = new_tag(&alice, "Shared").unwrap();
    let f = new_card(&alice, team, "private now").unwrap();
    place(&alice, team, f).unwrap();
    let b = introduce(&mut w, &alice, &bob);
    share(&alice, team, b, Role::Read, None).unwrap();
    w.run();
    assert_eq!(text(&bob, f).unwrap().as_deref(), Some("private now"));
    let mine = alice.move_thing(f, alice.me(), Place::In(alice.home())).unwrap();
    assert_ne!(mine, f);
    assert!(alice.same_thing(mine, f));
    w.run();
    assert_eq!(text(&alice, mine).unwrap().as_deref(), Some("private now"));
    assert_eq!(text(&bob, mine).unwrap(), None, "the copy is the person's own");
}
