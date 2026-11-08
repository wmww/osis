//! `contact:*`: a person's fields.

use crate::contact::{EMAILS, Labeled, NAMES, NICKNAME, Names, ORG, PHONES, PROFILE, names, org};
use osis_kit::facets::fields::{Edit, Row};
use osis_kit::store::Data;
use osis_kit::view::{Action, Block, Cx, Do, Facet, FormRow as Row2, Icon, Input, Mark, Offer, Section, Summary};
use osis::{Path, Result, Tid};

/// What saving a form row does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormAct {
    /// Writes the row's value at its path.
    Field(Row),
    /// Renames a map entry (an email address, a phone number); empty text removes it.
    RenameKey { ak: &'static str, old: String },
    /// Adds a map entry keyed by the text.
    AddKey { ak: &'static str },
}

/// A row of a kind's own form (a contact's fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormRow {
    pub label: String,
    pub value: String,
    pub placeholder: String,
    pub act: FormAct,
}

fn text_row(ak: &str, path: Path, label: &str, value: String, optional: bool) -> Row {
    Row { ak: ak.into(), path, depth: 0, label: label.into(), ty: String::new(), value, edit: Edit::Text, optional }
}

/// A contact's form: names, nickname, title, organisation, emails, phones.
pub fn contact_form(d: &Data, t: Tid) -> Result<Vec<FormRow>> {
    let n = d.db.at(t, NAMES).get()?;
    let o = d.db.at(t, ORG).get()?;
    let field = |label: &str, ph: &str, row: Row| FormRow { label: label.into(), value: row.value.clone(), placeholder: ph.into(), act: FormAct::Field(row) };
    let mut out = vec![
        field("Given name", "", text_row("contact:names.0", Path::root().push(names::GIVEN), "given", n.as_ref().and_then(|n| n.given.clone()).unwrap_or_default(), true)),
        field("Family name", "", text_row("contact:names.0", Path::root().push(names::FAMILY), "family", n.as_ref().and_then(|n| n.family.clone()).unwrap_or_default(), true)),
        field("Nickname", "", text_row("contact:nickname.0", Path::root(), "nickname", d.db.at(t, NICKNAME).get()?.unwrap_or_default(), false)),
        field("Title", "", text_row("contact:org.0", Path::root().push(org::TITLE), "title", o.as_ref().map(|o| o.title.clone()).unwrap_or_default(), false)),
        field("Organisation", "", text_row("contact:org.0", Path::root().push(org::NAME), "name", o.as_ref().map(|o| o.name.clone()).unwrap_or_default(), false)),
    ];
    for (ak, key, label, add) in [("contact:emails.0", EMAILS, "Email", "Add an email"), ("contact:phones.0", PHONES, "Phone", "Add a phone")] {
        for k in d.db.at(t, key).get()?.unwrap_or_default().into_keys() {
            out.push(FormRow { label: label.into(), value: k.clone(), placeholder: "removed when empty".into(), act: FormAct::RenameKey { ak, old: k } });
        }
        out.push(FormRow { label: label.into(), value: String::new(), placeholder: add.into(), act: FormAct::AddKey { ak } });
    }
    Ok(out)
}

/// Saves a form row's text.
pub fn form_apply(d: &Data, t: Tid, act: &FormAct, text: &str) -> Result<()> {
    let text = text.trim();
    match act {
        // a field of an absent struct is written alone (reads fill the others from defaults):
        // writing the whole struct first would overwrite a concurrent write to a sibling
        FormAct::Field(row) => d.set_field(t, row, text),
        FormAct::RenameKey { ak, old } => {
            let key = d.db.aspect_key(ak)?;
            let entry: Labeled = d.db.at(t, key.clone()).path(Path::root().push(old.as_str())).get()?.unwrap_or(Labeled { label: String::new(), pref: false });
            if text == old {
                return Ok(());
            }
            let mut w = d.db.write();
            w.at(t, key.clone()).path(Path::root().push(old.as_str())).remove()?;
            if !text.is_empty() {
                w.at(t, key.clone()).path(Path::root().push(text)).set(&entry)?;
            }
            w.commit()?;
            Ok(())
        }
        FormAct::AddKey { ak } => {
            if text.is_empty() {
                return Ok(());
            }
            let key = d.db.aspect_key(ak)?;
            let mut w = d.db.write();
            w.at(t, key).path(Path::root().push(text)).set(&Labeled { label: String::new(), pref: false })?;
            w.commit()?;
            Ok(())
        }
    }
}


pub struct ContactFacet;
pub static FACET: ContactFacet = ContactFacet;

#[derive(Clone, Debug, PartialEq)]
struct Save(Tid, FormAct);

impl Action for Save {
    fn run(&self, cx: &Cx<'_>, input: &Input) -> Result<()> {
        let Input::Text(text) = input else { return Ok(()) };
        form_apply(cx.data, self.0, &self.1, text)
    }
}

fn start(_: &Data, w: &mut osis::Write<'_>, t: Tid, _g: Tid) -> Result<()> {
    w.at(t, NAMES).set(&Names { given: None, family: None, middle: None, prefix: None, suffix: None })
}

fn initials(name: &str) -> String {
    let s: String = name.split_whitespace().filter_map(|w| w.chars().next()).take(2).collect();
    if s.is_empty() { "?".into() } else { s.to_uppercase() }
}

impl Facet for ContactFacet {
    fn id(&self) -> &'static str {
        "contact"
    }
    fn claims(&self, ak: &str) -> bool {
        ak.starts_with("contact:")
    }
    fn summarize(&self, cx: &Cx<'_>, t: Tid, s: &mut Summary) -> Result<()> {
        s.words.insert(0, "Person".into());
        s.mark = Mark::Initials(initials(&s.name));
        s.profile = cx.data.db.at(t, PROFILE).get()?;
        if s.sub.is_empty() {
            let org = cx.data.db.at(t, ORG).get()?.map(|o| if o.title.is_empty() { o.name } else { o.title }).filter(|x| !x.is_empty());
            s.sub = match org {
                Some(o) => o,
                None => cx.data.db.at(t, EMAILS).get()?.and_then(|m| m.into_keys().next()).unwrap_or_else(|| "Contact".into()),
            };
        }
        Ok(())
    }
    fn show(&self, cx: &Cx<'_>, t: Tid) -> Result<Section> {
        let rows = contact_form(cx.data, t)?.into_iter().map(|r| Row2 { label: r.label, sub: String::new(), depth: 0, value: r.value, placeholder: r.placeholder, save: Some(Do::new(Save(t, r.act))) }).collect();
        Ok(Section::of(vec![Block::Form { rows, wide: false }]))
    }
    fn search(&self, cx: &Cx<'_>, t: Tid) -> Result<Vec<String>> {
        let mut parts = Vec::new();
        if let Some(o) = cx.data.db.at(t, ORG).get()? {
            parts.extend([o.name, o.department, o.title]);
        }
        parts.extend(cx.data.db.at(t, EMAILS).get()?.unwrap_or_default().into_keys());
        parts.extend(cx.data.db.at(t, PHONES).get()?.unwrap_or_default().into_keys());
        Ok(parts.into_iter().filter(|s| !s.is_empty()).collect())
    }
    fn offers(&self, cx: &Cx<'_>, t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(match t {
            Some(t) if cx.has(t, "contact:")? => Vec::new(),
            Some(_) => vec![Offer { id: "person-fields", label: "Person fields", icon: Icon::Contact, set: start }],
            None => vec![Offer { id: "person", label: "Person", icon: Icon::Contact, set: start }],
        })
    }
}
