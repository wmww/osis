//! Demo data (`osis-app DIR --demo`): tags, people, notes and events to play with, written once
//! per person (marked `/osis-app/demo` on the app group).

use crate::contact::{EMAILS, Labeled, ORG, Org, PHONES};
use crate::data::Data;
use crate::event::{END, End, LOCATION, START, Start, Wall};
use crate::schema::{COLOR, DEMO, FAVORITES};
use osis::core::{BODY, NAME, TAG, Tag};
use osis::{Result, Tid, Write};
use std::collections::BTreeMap;

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

struct Ctx<'a, 'w> {
    w: &'a mut Write<'w>,
    me: Tid,
    group: Tid,
    names: BTreeMap<&'static str, Tid>,
}

impl Ctx<'_, '_> {
    fn thing(&mut self, key: &'static str, name: &str, tags: &[&str]) -> Result<Tid> {
        let t = self.w.create(self.me)?;
        self.w.at(t, NAME).set(&name.to_string())?;
        self.w.place(t, self.group)?;
        for g in tags {
            if let Some(g) = self.names.get(g).copied() {
                self.w.place(t, g)?;
            }
        }
        self.names.insert(key, t);
        Ok(t)
    }

    fn tag(&mut self, key: &'static str, name: &str, color: &str, parent: Option<&str>) -> Result<Tid> {
        let t = self.thing(key, name, &[])?;
        self.w.make_group(t)?;
        self.w.at(t, TAG).set(&Tag { color: Some(color.into()) })?;
        // a subgroup of the app group, so its items sync
        self.w.add_subgroup(self.group, t)?;
        if let Some(p) = parent.and_then(|p| self.names.get(p).copied()) {
            self.w.add_subgroup(p, t)?;
        }
        Ok(t)
    }

    fn note(&mut self, key: &'static str, name: &str, tags: &[&str], body: &str) -> Result<Tid> {
        let t = self.thing(key, name, tags)?;
        self.w.at(t, BODY).set(&body.to_string())?;
        Ok(t)
    }

    #[allow(clippy::too_many_arguments)]
    fn contact(&mut self, key: &'static str, name: &str, color: &str, title: &str, email: &str, phone: &str, body: &str) -> Result<Tid> {
        let t = self.thing(key, name, &[])?;
        self.w.at(t, COLOR).set(&color.to_string())?;
        self.w.at(t, ORG).set(&Org { name: String::new(), department: String::new(), title: title.into() })?;
        let lab = Labeled { label: String::new(), pref: true };
        self.w.at(t, EMAILS).set(&BTreeMap::from([(email.to_string(), lab.clone())]))?;
        if !phone.is_empty() {
            self.w.at(t, PHONES).set(&BTreeMap::from([(phone.to_string(), lab)]))?;
        }
        if !body.is_empty() {
            self.w.at(t, BODY).set(&body.to_string())?;
        }
        Ok(t)
    }

    /// An event `day` days after this week's Monday, `h` hours (fractional) for `len` hours.
    #[allow(clippy::too_many_arguments)]
    fn event(&mut self, key: &'static str, name: &str, tags: &[&str], monday: i64, day: i64, h: f64, len: f64, place: &str, body: &str) -> Result<Tid> {
        let t = self.thing(key, name, tags)?;
        let start = monday + day * DAY_MS + (h * HOUR_MS as f64) as i64;
        self.w.at(t, START).set(&Start::At(Wall { time: start, zone: None }))?;
        self.w.at(t, END).set(&End::After((len * HOUR_MS as f64) as i64))?;
        self.w.at(t, LOCATION).set(&place.to_string())?;
        if !body.is_empty() {
            self.w.at(t, BODY).set(&body.to_string())?;
        }
        Ok(t)
    }
}

/// This week's Monday 00:00 as a floating wall time (`localtime` ms), from `now_ms` (UTC; the
/// zone offset is ignored until the app reads the local zone).
pub fn monday_of(now_ms: i64) -> i64 {
    let days = now_ms.div_euclid(DAY_MS);
    // 1970-01-01 was a Thursday
    let weekday = (days + 3).rem_euclid(7);
    (days - weekday) * DAY_MS
}

/// Adds the demo data unless this person has it already; returns whether it added it.
pub fn add(data: &Data) -> Result<bool> {
    if data.has_demo()? {
        return Ok(false);
    }
    let group = data.main_group()?;
    let db = &data.db;
    let monday = monday_of(i64::try_from(db.now().0).unwrap_or(0));
    let views: Vec<Tid> = data.views()?.into_iter().map(|(_, t)| t).collect();
    // the person's own favorites stay, after the demo's
    let had = data.favorites()?;
    let base = data.get(group, FAVORITES)?.unwrap_or_default();
    db.write_with(|w| {
        let mut c = Ctx { w, me: db.me(), group, names: BTreeMap::new() };
        c.tag("home", "Home", "#f59e0b", None)?;
        c.tag("work", "Work", "#3b82f6", None)?;
        c.tag("garden", "Garden", "#22c55e", Some("home"))?;
        c.tag("recipes", "Recipes", "#ef4444", Some("home"))?;
        c.tag("lisbon", "Lisbon trip", "#ec4899", None)?;
        c.tag("reading", "Reading", "#a855f7", None)?;

        c.contact("mara", "Mara Okafor", "#e11d48", "Friend · climbing", "mara@okafor.me", "+44 7700 900123", "Allergic to walnuts. Birthday in March.")?;
        c.contact("jun", "Jun Takahashi", "#2563eb", "Design lead", "jun@studio-kei.jp", "+81 90 1234 5678", "")?;
        c.contact("ana", "Ana Ribeiro", "#d97706", "Our host in Lisbon", "ana.ribeiro@mail.pt", "+351 912 345 678", "Keys with the café downstairs.")?;
        c.contact("theo", "Theo Lindqvist", "#059669", "Neighbour, allotment 14", "theo.l@posteo.se", "", "Has spare seed potatoes every spring.")?;
        c.contact("sam", "Sam Patel", "#7c3aed", "Engineering", "sam@work.example", "+1 415 555 0134", "")?;
        c.contact("iris", "Iris Novak", "#0891b2", "Book club", "iris@novak.cz", "", "")?;

        c.note("groceries", "Groceries", &["home"], "oat milk\neggs\nsourdough\nlemons\nbasil for the pesto\ncoffee beans (the Ethiopian one)")?;
        c.note("pesto", "Wild garlic pesto", &["recipes"], "100 g wild garlic, 50 g parmesan, 40 g toasted pine nuts (not walnuts, Mara), olive oil until loose, lemon zest.\n\nBlitz briefly. Keeps a week under a layer of oil.")?;
        c.note("tomatoes", "Tomato varieties", &["garden"], "Sungold: sweetest, splits after rain\nBlack Krim: great flavour, low yield\nGardener's Delight: reliable\n\nTry San Marzano for sauce next year. Ask Theo about blight-resistant ones.")?;
        c.note("compost", "Compost notes", &["garden"], "Browns to greens about 3:1. Turn every two weeks. The far bin is ready in May.")?;
        c.note("itinerary", "Itinerary", &["lisbon"], "Thu: land 10:40, bags to Ana's, lunch at the market\nFri: tram 28, Alfama, miradouro at sunset\nSat: Sintra day trip\nSun: pastéis de nata class, flight 19:55")?;
        c.note("packing", "Packing list", &["lisbon"], "walking shoes\nsunscreen\nadapter (EU)\nlight jacket for Sintra\nbook for the flight")?;
        c.note("q4", "Q4 planning", &["work"], "Ship the sync redesign before December freeze.\nHire: one more backend person.\nOffsite: Lisbon? (ha)")?;
        c.note("books", "Books to read", &["reading"], "The Dispossessed: Le Guin\nPiranesi: Clarke\nThe Mushroom at the End of the World: Tsing\nBraiding Sweetgrass: Kimmerer")?;
        c.note("ideas", "Ideas", &[], "A calendar that shows what I wrote that day, not just what I planned.\nTags as colours of the whole UI?\nShared shopping list with Mara for the trip.")?;

        c.event("standup", "Team standup", &["work"], monday, 0, 9.5, 0.25, "Video call", "")?;
        c.event("dentist", "Dentist", &[], monday, 0, 16.0, 0.75, "Bridge St Clinic", "")?;
        c.event("jun1", "1:1 with Jun", &["work"], monday, 1, 11.0, 0.5, "Room 3B", "Agenda\n- feedback on the tags prototype\n- hiring loop\n- her offsite idea")?;
        c.event("dinner", "Dinner with Mara", &["home"], monday, 1, 19.0, 2.5, "Tavola, Kings Rd", "")?;
        c.event("seeds", "Seed swap", &["garden"], monday, 2, 10.0, 2.0, "Library, hall 2", "Bring: spare Sungold seeds, runner beans. Looking for: San Marzano, borlotti.")?;
        c.event("club", "Book club", &["reading"], monday, 2, 19.5, 1.5, "Iris's flat", "")?;
        c.event("flight", "Flight to Lisbon", &["lisbon"], monday, 3, 7.17, 3.5, "LGW → LIS, TP1331", "")?;
        c.event("sintra", "Sintra day trip", &["lisbon"], monday, 5, 9.0, 9.0, "Rossio station", "")?;
        c.event("nata", "Pastéis de nata class", &["lisbon", "recipes"], monday, 6, 11.0, 2.0, "Rua da Prata 12", "Write the recipe down properly this time.")?;

        let pick = |k: &str| c.names.get(k).copied();
        let mut favs: Vec<Tid> = ["groceries", "lisbon", "mara", "garden", "ideas"].iter().filter_map(|k| pick(k)).collect();
        favs.splice(1..1, views.iter().take(2).copied());
        favs.extend(had.iter().filter(|t| !views.iter().take(2).any(|v| v == *t)));
        c.w.at(group, FAVORITES).edit(&base, &favs)?;
        c.w.at(group, DEMO).set(&true)?;
        Ok(())
    })?;
    Ok(true)
}
