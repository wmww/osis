//! The schema fallback view (notes/app.md Model): every aspect of a thing, read and edited from
//! its schema-declared type alone. Values are flattened into rows down to scalars (structs by
//! field, maps by key, enum payloads, `option`s as their value or empty); a scalar row is
//! edited as text and written at its path. Lists, sets, counters, texts and untyped values are
//! shown, not edited.

use crate::data::Data;
use osis::{Float, NestedType, Path, Result, Step, Tid, Value, ValueType};

/// How a row's text is turned back into a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    None,
    Text,
    Int,
    Float,
    Bool,
    /// A case of a payload-free enum, by name.
    Case,
}

/// One row of the fallback view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub ak: String,
    pub path: Path,
    /// Nesting below the aspect (0: the aspect itself).
    pub depth: usize,
    /// The aspect key or field / key / case name.
    pub label: String,
    /// The declared type, short (`string`, `date`, `option<string>`, ...).
    pub ty: String,
    /// The value as text (`""` for none).
    pub value: String,
    pub edit: Edit,
    /// The row is an `option`: empty text writes `none`.
    pub optional: bool,
}

/// Core aspects that are the system's, not the user's.
const HIDDEN: [&str; 12] = ["created.0", "group.0", "placed.0~", "groups.0", "roles.0", "keys.0", "secrets.0", "label.0", "reach.0", "seen.0", "tenures.0", "node.0"];

impl Data {
    /// The fallback view's rows for `t`, by aspect key.
    pub fn field_rows(&self, t: Tid) -> Result<Vec<Row>> {
        let mut aks: Vec<String> = self.db.aspects(t)?.into_iter().map(|a| a.as_str().to_string()).collect();
        aks.retain(|a| !HIDDEN.contains(&a.as_str()));
        aks.sort();
        let mut rows = Vec::new();
        for ak in aks {
            let key = self.db.key(&ak)?;
            let value = match self.db.at(t, key.clone()).get() {
                Ok(v) => v,
                // shown read-only: an empty editable row could overwrite it
                Err(e @ osis::Error::TooLarge { .. }) => {
                    rows.push(Row { ak: ak.clone(), path: Path::root(), depth: 0, label: ak.clone(), ty: "unreadable".into(), value: e.to_string(), edit: Edit::None, optional: false });
                    continue;
                }
                Err(e) => return Err(e),
            };
            match key.value_type() {
                Some(ty) => flatten(&ak, &ty.name(), &ty.get(), value.as_ref(), Path::root(), ak.clone(), 0, &mut rows),
                None => rows.push(Row { ak: ak.clone(), path: Path::root(), depth: 0, label: ak.clone(), ty: "untyped".into(), value: value.map(|v| show(&v)).unwrap_or_default(), edit: Edit::None, optional: false }),
            }
        }
        Ok(rows)
    }

    /// Writes the text of an edited row. An unparsable number or case is `Invalid`.
    pub fn set_field(&self, t: Tid, row: &Row, text: &str) -> Result<()> {
        let key = self.db.key(&row.ak)?;
        let text = text.trim();
        let v = if row.optional && text.is_empty() {
            Value::Enum(0, None)
        } else {
            let inner = match row.edit {
                Edit::None => return Ok(()),
                Edit::Text => Value::Str(text.to_string()),
                Edit::Int => Value::Int(text.parse().map_err(|_| osis::Error::Invalid(format!("{text:?} is not a whole number")))?),
                Edit::Float => Value::Float(Float::new(text.parse().map_err(|_| osis::Error::Invalid(format!("{text:?} is not a number")))?)),
                Edit::Bool => Value::Bool(match text.to_lowercase().as_str() {
                    "true" | "yes" | "1" | "on" => true,
                    "false" | "no" | "0" | "off" => false,
                    _ => return Err(osis::Error::Invalid(format!("{text:?}: true or false"))),
                }),
                Edit::Case => {
                    let ty = key.value_type().ok_or_else(|| osis::Error::Invalid("untyped".into()))?.get();
                    let ty = type_at(ty, &row.path, row.optional).ok_or_else(|| osis::Error::Invalid("no type".into()))?;
                    let ValueType::Cases(cases) = ty else { return Ok(()) };
                    let id = cases.iter().find(|c| c.name == text).map(|c| c.id).ok_or_else(|| osis::Error::Invalid(format!("{text:?}: one of {}", cases.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "))))?;
                    Value::Enum(id, None)
                }
            };
            if row.optional { Value::Enum(1, Some(Box::new(inner))) } else { inner }
        };
        let mut w = self.db.write();
        w.at(t, key).path(row.path.clone()).set(&v)?;
        w.commit()?;
        Ok(())
    }
}

/// The type at `path` below `ty` (through an `option` when `optional`: the row's own type is the
/// payload's).
fn type_at(mut ty: ValueType, path: &Path, optional: bool) -> Option<ValueType> {
    for step in path.steps() {
        ty = match (&ty, step) {
            (ValueType::Record(fields), Step::Field(id)) => fields.iter().find(|f| f.id == *id)?.ty.get(),
            (ValueType::Cases(cases), Step::Case(id)) => cases.iter().find(|c| c.id == *id)?.value.as_ref()?.get(),
            (ValueType::Optional(p), Step::Case(1)) => p.get(),
            (ValueType::Map(_, v), Step::Key(_)) => v.get(),
            _ => return None,
        };
    }
    if optional && let ValueType::Optional(p) = &ty {
        ty = p.get();
    }
    Some(ty)
}

#[allow(clippy::too_many_arguments)]
fn flatten(ak: &str, name: &str, ty: &ValueType, v: Option<&Value>, path: Path, label: String, depth: usize, out: &mut Vec<Row>) {
    let row = |value: String, edit: Edit, optional: bool| Row { ak: ak.into(), path: path.clone(), depth, label: label.clone(), ty: name.to_string(), value, edit, optional };
    let nested = |t: &NestedType, v: Option<&Value>, path: Path, label: String, out: &mut Vec<Row>| flatten(ak, &t.name(), &t.get(), v, path, label, depth + 1, out);
    if let ValueType::Optional(inner) = ty {
        // an option of a scalar is one row; of anything else, its payload's rows when set
        let payload = match v {
            Some(Value::Enum(1, Some(p))) => Some(&**p),
            _ => None,
        };
        match scalar(&inner.get()) {
            Some(edit) => out.push(row(payload.map(show).unwrap_or_default(), edit, true)),
            None => {
                out.push(row(if payload.is_some() { String::new() } else { "none".into() }, Edit::None, false));
                if let Some(p) = payload {
                    nested(inner, Some(p), path.clone().push(Step::Case(1)), "some".into(), out);
                }
            }
        }
        return;
    }
    if let Some(edit) = scalar(ty) {
        let text = match (v, ty) {
            (Some(Value::Enum(id, _)), ValueType::Cases(cases)) => cases.iter().find(|c| c.id == *id).map(|c| c.name.clone()).unwrap_or_default(),
            (Some(v), _) => show(v),
            (None, _) => String::new(),
        };
        out.push(row(text, edit, false));
        return;
    }
    match ty {
        ValueType::Record(fields) => {
            out.push(row(String::new(), Edit::None, false));
            for f in fields {
                let fv = match v {
                    Some(Value::Map(m)) => m.get(&Value::Int(i64::try_from(f.id).unwrap_or(i64::MAX))),
                    _ => None,
                };
                nested(&f.ty, fv.or(f.default.as_ref()), path.clone().push(Step::Field(f.id)), f.name.clone(), out);
            }
        }
        ValueType::Cases(cases) => {
            let (id, payload) = match v {
                Some(Value::Enum(id, p)) => (Some(*id), p.as_deref()),
                _ => (None, None),
            };
            let case = id.and_then(|i| cases.iter().find(|c| c.id == i));
            out.push(row(case.map(|c| c.name.clone()).unwrap_or_default(), Edit::None, false));
            if let (Some(c), Some(p)) = (case, payload)
                && let Some(pt) = &c.value
            {
                nested(pt, Some(p), path.clone().push(Step::Case(c.id)), c.name.clone(), out);
            }
        }
        ValueType::Map(_, vt) => {
            let m = match v {
                Some(Value::Map(m)) => m.clone(),
                _ => Default::default(),
            };
            out.push(row(if m.is_empty() { "empty".into() } else { String::new() }, Edit::None, false));
            for (k, ev) in &m {
                nested(vt, Some(ev), path.clone().push(Step::Key(k.clone())), show(k), out);
            }
        }
        _ => out.push(row(v.map(show).unwrap_or_default(), Edit::None, false)),
    }
}

/// How a scalar type is edited; `None` for a composite.
fn scalar(t: &ValueType) -> Option<Edit> {
    Some(match t {
        ValueType::String => Edit::Text,
        // a text (a body) is edited in its own session, which merges per character; a
        // one-line row would also flatten its lines
        ValueType::Text => Edit::None,
        ValueType::Int | ValueType::Time | ValueType::Duration | ValueType::Date | ValueType::LocalTime => Edit::Int,
        ValueType::Float => Edit::Float,
        ValueType::Bool => Edit::Bool,
        ValueType::Cases(c) if c.iter().all(|c| c.value.is_none()) => Edit::Case,
        ValueType::Thing | ValueType::Bytes => Edit::None,
        _ => return None,
    })
}

/// A value as one line of text.
pub fn show(v: &Value) -> String {
    match v {
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.get().to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Str(s) => s.clone(),
        Value::Bytes(b) => format!("{} bytes", b.len()),
        Value::Tid(t) => t.to_string(),
        Value::Enum(c, None) => format!("#{c}"),
        Value::Enum(c, Some(p)) => format!("#{c}({})", show(p)),
        Value::Map(m) => format!("{{{}}}", m.iter().map(|(k, v)| format!("{}: {}", show(k), show(v))).collect::<Vec<_>>().join(", ")),
        Value::List(l) => format!("[{}]", l.iter().map(show).collect::<Vec<_>>().join(", ")),
        Value::Set(s) => format!("{{{}}}", s.iter().map(show).collect::<Vec<_>>().join(", ")),
        other => format!("{other:?}"),
    }
}

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

impl Data {
    /// A contact's form: names, nickname, title, organisation, emails, phones.
    pub fn contact_form(&self, t: Tid) -> Result<Vec<FormRow>> {
        use crate::contact::{EMAILS, NAMES, NICKNAME, ORG, PHONES, names, org};
        let n = self.db.at(t, NAMES).get()?;
        let o = self.db.at(t, ORG).get()?;
        let field = |label: &str, ph: &str, row: Row| FormRow { label: label.into(), value: row.value.clone(), placeholder: ph.into(), act: FormAct::Field(row) };
        let mut out = vec![
            field("Given name", "", text_row("contact:names.0", Path::root().push(names::GIVEN), "given", n.as_ref().and_then(|n| n.given.clone()).unwrap_or_default(), true)),
            field("Family name", "", text_row("contact:names.0", Path::root().push(names::FAMILY), "family", n.as_ref().and_then(|n| n.family.clone()).unwrap_or_default(), true)),
            field("Nickname", "", text_row("contact:nickname.0", Path::root(), "nickname", self.db.at(t, NICKNAME).get()?.unwrap_or_default(), false)),
            field("Title", "", text_row("contact:org.0", Path::root().push(org::TITLE), "title", o.as_ref().map(|o| o.title.clone()).unwrap_or_default(), false)),
            field("Organisation", "", text_row("contact:org.0", Path::root().push(org::NAME), "name", o.as_ref().map(|o| o.name.clone()).unwrap_or_default(), false)),
        ];
        for (ak, key, label, add) in [("contact:emails.0", EMAILS, "Email", "Add an email"), ("contact:phones.0", PHONES, "Phone", "Add a phone")] {
            for k in self.db.at(t, key).get()?.unwrap_or_default().into_keys() {
                out.push(FormRow { label: label.into(), value: k.clone(), placeholder: "removed when empty".into(), act: FormAct::RenameKey { ak, old: k } });
            }
            out.push(FormRow { label: label.into(), value: String::new(), placeholder: add.into(), act: FormAct::AddKey { ak } });
        }
        Ok(out)
    }

    /// Saves a form row's text.
    pub fn form_apply(&self, t: Tid, act: &FormAct, text: &str) -> Result<()> {
        use crate::contact::Labeled;
        let text = text.trim();
        match act {
            // a field of an absent struct is written alone (reads fill the others from defaults):
            // writing the whole struct first would overwrite a concurrent write to a sibling
            FormAct::Field(row) => self.set_field(t, row, text),
            FormAct::RenameKey { ak, old } => {
                let key = self.db.key(ak)?;
                let entry: Labeled = self.db.at(t, key.clone()).path(Path::root().push(old.as_str())).get()?.unwrap_or(Labeled { label: String::new(), pref: false });
                if text == old {
                    return Ok(());
                }
                let mut w = self.db.write();
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
                let key = self.db.key(ak)?;
                let mut w = self.db.write();
                w.at(t, key).path(Path::root().push(text)).set(&Labeled { label: String::new(), pref: false })?;
                w.commit()?;
                Ok(())
            }
        }
    }
}
