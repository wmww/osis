//! `body.0`: a thing's text.

use crate::view::{Block, Cx, Facet, Icon, Offer, Section, Summary, TextRole};
use osis::core::BODY;
use osis::{Result, Tid};

pub struct BodyFacet;
pub static FACET: BodyFacet = BodyFacet;

/// A body to write in.
fn start(_: &crate::store::Data, w: &mut osis::Write<'_>, t: Tid, _g: Tid) -> Result<()> {
    w.at(t, BODY).set(&String::new())
}

/// A new thing is a note: nothing to write beyond what creation does.
fn note(_: &crate::store::Data, _: &mut osis::Write<'_>, _: Tid, _: Tid) -> Result<()> {
    Ok(())
}

/// The first non-blank line, trimmed.
fn first_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

impl Facet for BodyFacet {
    fn id(&self) -> &'static str {
        "body"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "body.0"
    }
    fn summarize(&self, cx: &Cx<'_>, t: Tid, s: &mut Summary) -> Result<()> {
        let body = cx.data.db.at(t, BODY).get()?.unwrap_or_default();
        if !body.is_empty() {
            s.words.push("Note".into());
        }
        if s.sub.is_empty() {
            s.sub = first_line(&body).unwrap_or("Empty note").to_string();
        }
        Ok(())
    }
    fn show(&self, cx: &Cx<'_>, t: Tid) -> Result<Section> {
        if cx.config().flag("read_only") {
            return Ok(Section::of(vec![Block::Line(cx.data.db.at(t, BODY).get()?.unwrap_or_default())]));
        }
        Ok(Section::of(vec![Block::Editor { thing: t, ak: "body.0".into(), key: None, placeholder: "Write something…".into(), role: TextRole::Body, multiline: true, lead: None }]))
    }
    fn search(&self, cx: &Cx<'_>, t: Tid) -> Result<Vec<String>> {
        Ok(cx.data.db.at(t, BODY).get()?.into_iter().collect())
    }
    fn offers(&self, cx: &Cx<'_>, t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(match t {
            None => vec![Offer { id: "note", label: "Note", icon: Icon::Note, set: note }],
            Some(t) if cx.has(t, "body.0")? => Vec::new(),
            Some(_) => vec![Offer { id: "text", label: "Text", icon: Icon::Note, set: start }],
        })
    }
}
