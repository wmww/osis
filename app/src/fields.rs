//! The schema fallback view (notes/app.md Model): every aspect of a thing, read and edited from
//! its schema-declared type alone. Values are flattened into rows down to scalars (structs by
//! field, maps by key, enum payloads, `option`s as their value or empty); a scalar row is
//! edited as text and written at its path. Lists, sets, counters and untyped values are shown,
//! not edited.

use crate::data::Data;
use osis::schema::{Schema, Step, Type};
use osis::{Path, Result, Tid, Value};

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
const HIDDEN: [&str; 13] = ["/created", "/group", "/groups", "/members", "/keys", "/secrets", "/label", "/reach", "/seen", "/tenures", "/node", "/moved", "/was"];

impl Data {
    /// The fallback view's rows for `t`, by aspect key.
    pub fn field_rows(&self, t: Tid) -> Result<Vec<Row>> {
        let mut aks: Vec<String> = self.db.aspects(t)?.into_iter().map(|a| a.as_str().to_string()).collect();
        aks.retain(|a| !HIDDEN.contains(&a.as_str()));
        aks.sort();
        let mut rows = Vec::new();
        for ak in aks {
            let key = self.db.key(&ak)?;
            let value = self.db.get(t, key.clone()).ok().flatten();
            let schema = key.schema().cloned();
            match (schema.as_deref(), schema.as_deref().and_then(|s| s.aspects.get(&ak)).map(|d| d.ty.clone())) {
                (Some(s), Some(ty)) => flatten(s, &ak, &ty, value.as_ref(), Path::root(), ak.clone(), 0, &mut rows),
                _ => rows.push(Row { ak: ak.clone(), path: Path::root(), depth: 0, label: ak.clone(), ty: "untyped".into(), value: value.map(|v| show(&v)).unwrap_or_default(), edit: Edit::None, optional: false }),
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
                Edit::Float => Value::Float(osis::schema::osis_base::Float::new(text.parse().map_err(|_| osis::Error::Invalid(format!("{text:?} is not a number")))?)),
                Edit::Bool => Value::Bool(matches!(text.to_lowercase().as_str(), "true" | "yes" | "1" | "on")),
                Edit::Case => {
                    let schema = key.schema().cloned().ok_or_else(|| osis::Error::Invalid("untyped".into()))?;
                    let ty = type_at(&schema, &row.ak, &row.path, row.optional).ok_or_else(|| osis::Error::Invalid("no type".into()))?;
                    let Type::Enum(e) = ty else { return Ok(()) };
                    let id = e.cases.iter().find(|(_, c)| c.name == text).map(|(id, _)| *id).ok_or_else(|| osis::Error::Invalid(format!("{text:?}: one of {}", e.cases.values().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "))))?;
                    Value::Enum(id, None)
                }
            };
            if row.optional { Value::Enum(1, Some(Box::new(inner))) } else { inner }
        };
        self.db.write_with(|w| w.at(t, key.clone()).path(row.path.clone()).set(&v))
    }
}

/// The expanded type at `path` of aspect `ak` (through `option`s when `optional`, the row's own
/// type is the payload's).
fn type_at(s: &Schema, ak: &str, path: &Path, optional: bool) -> Option<Type> {
    let mut ty = s.expand(&s.aspects.get(ak)?.ty).ok()?.into_owned();
    for step in path.steps() {
        ty = match (&ty, step) {
            (Type::Struct(st), Step::Field(id)) => st.fields.get(id)?.ty.clone(),
            (Type::Enum(e), Step::Case(id)) => e.cases.get(id)?.payload.clone()?,
            (Type::Map(_, v), Step::Key(_)) => (**v).clone(),
            _ => return None,
        };
        ty = s.expand(&ty).ok()?.into_owned();
    }
    if optional && let Type::Enum(e) = &ty {
        ty = s.expand(&e.cases.get(&1)?.payload.clone()?).ok()?.into_owned();
    }
    Some(ty)
}

/// A short name for a declared type.
fn type_name(t: &Type) -> String {
    match t {
        Type::String => "string".into(),
        Type::Blob => "blob".into(),
        Type::Bool => "bool".into(),
        Type::Int => "int".into(),
        Type::Float => "float".into(),
        Type::Tid => "tid".into(),
        Type::Any => "any".into(),
        Type::Text => "text".into(),
        Type::List(e) => format!("list<{}>", type_name(e)),
        Type::Set(e) => format!("set<{}>", type_name(e)),
        Type::Map(k, v) => format!("map<{}, {}>", type_name(k), type_name(v)),
        Type::Struct(_) => "struct".into(),
        Type::Enum(_) => "enum".into(),
        Type::Counter(e) => format!("counter<{}>", type_name(e)),
        Type::Max(e) => format!("max<{}>", type_name(e)),
        Type::Min(e) => format!("min<{}>", type_name(e)),
        Type::Named(n, args) if args.is_empty() => n.clone(),
        Type::Named(n, args) => format!("{n}<{}>", args.iter().map(type_name).collect::<Vec<_>>().join(", ")),
        Type::Param(p) => p.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn flatten(s: &Schema, ak: &str, declared: &Type, v: Option<&Value>, path: Path, label: String, depth: usize, out: &mut Vec<Row>) {
    let name = type_name(declared);
    let row = |value: String, edit: Edit, optional: bool| Row { ak: ak.into(), path: path.clone(), depth, label: label.clone(), ty: name.clone(), value, edit, optional };
    if s.is_option(declared) {
        // an option of a scalar is one row; of anything else, its payload's rows when set
        let inner_decl = match declared {
            Type::Named(_, args) => args.first().cloned(),
            _ => None,
        };
        let inner = s.expand(declared).ok().and_then(|t| match t.as_ref() {
            Type::Enum(e) => e.cases.get(&1).and_then(|c| c.payload.clone()),
            _ => None,
        });
        let payload = match v {
            Some(Value::Enum(1, Some(p))) => Some(&**p),
            _ => None,
        };
        let Some(inner) = inner.or(inner_decl) else { return };
        let expanded = s.expand(&inner).map(|c| c.into_owned()).unwrap_or(inner.clone());
        match scalar(&expanded) {
            Some(edit) => out.push(row(payload.map(show).unwrap_or_default(), edit, true)),
            None => {
                out.push(row(if payload.is_some() { String::new() } else { "none".into() }, Edit::None, false));
                if let Some(p) = payload {
                    flatten(s, ak, &inner, Some(p), path.clone().push(Step::Case(1)), "some".into(), depth + 1, out);
                }
            }
        }
        return;
    }
    let Ok(ty) = s.expand(declared) else {
        out.push(row(v.map(show).unwrap_or_default(), Edit::None, false));
        return;
    };
    if let Some(edit) = scalar(&ty) {
        let text = match (v, ty.as_ref()) {
            (Some(Value::Enum(id, _)), Type::Enum(e)) => e.cases.get(id).map(|c| c.name.clone()).unwrap_or_default(),
            (Some(v), _) => show(v),
            (None, _) => String::new(),
        };
        out.push(row(text, edit, false));
        return;
    }
    match ty.as_ref() {
        Type::Struct(st) => {
            out.push(row(String::new(), Edit::None, false));
            for (id, f) in &st.fields {
                let fv = match v {
                    Some(Value::Map(m)) => m.get(&Value::Int(i64::try_from(*id).unwrap_or(i64::MAX))),
                    _ => None,
                };
                let def = if fv.is_none() { s.default_of(f) } else { None };
                flatten(s, ak, &f.ty, fv.or(def.as_ref()), path.clone().push(Step::Field(*id)), f.name.clone(), depth + 1, out);
            }
        }
        Type::Enum(e) => {
            let (id, payload) = match v {
                Some(Value::Enum(id, p)) => (Some(*id), p.as_deref()),
                _ => (None, None),
            };
            let case = id.and_then(|i| e.cases.get(&i));
            out.push(row(case.map(|c| c.name.clone()).unwrap_or_default(), Edit::None, false));
            if let (Some(i), Some(c), Some(p)) = (id, case, payload)
                && let Some(pt) = &c.payload
            {
                flatten(s, ak, pt, Some(p), path.clone().push(Step::Case(i)), c.name.clone(), depth + 1, out);
            }
        }
        Type::Map(_, vt) => {
            let m = match v {
                Some(Value::Map(m)) => m.clone(),
                _ => Default::default(),
            };
            out.push(row(if m.is_empty() { "empty".into() } else { String::new() }, Edit::None, false));
            for (k, ev) in &m {
                flatten(s, ak, vt, Some(ev), path.clone().push(Step::Key(k.clone())), show(k), depth + 1, out);
            }
        }
        _ => out.push(row(v.map(show).unwrap_or_default(), Edit::None, false)),
    }
}

/// How a scalar type is edited; `None` for a composite.
fn scalar(t: &Type) -> Option<Edit> {
    Some(match t {
        Type::String | Type::Text => Edit::Text,
        Type::Int => Edit::Int,
        Type::Float => Edit::Float,
        Type::Bool => Edit::Bool,
        Type::Enum(e) if e.cases.values().all(|c| c.payload.is_none()) => Edit::Case,
        Type::Tid | Type::Blob => Edit::None,
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
        let n = self.get(t, NAMES)?;
        let o = self.get(t, ORG)?;
        let field = |label: &str, ph: &str, row: Row| FormRow { label: label.into(), value: row.value.clone(), placeholder: ph.into(), act: FormAct::Field(row) };
        let mut out = vec![
            field("Given name", "", text_row("/contact/names", Path::root().push(names::GIVEN), "given", n.as_ref().and_then(|n| n.given.clone()).unwrap_or_default(), true)),
            field("Family name", "", text_row("/contact/names", Path::root().push(names::FAMILY), "family", n.as_ref().and_then(|n| n.family.clone()).unwrap_or_default(), true)),
            field("Nickname", "", text_row("/contact/nickname", Path::root(), "nickname", self.get(t, NICKNAME)?.unwrap_or_default(), false)),
            field("Title", "", text_row("/contact/org", Path::root().push(org::TITLE), "title", o.as_ref().map(|o| o.title.clone()).unwrap_or_default(), false)),
            field("Organisation", "", text_row("/contact/org", Path::root().push(org::NAME), "name", o.as_ref().map(|o| o.name.clone()).unwrap_or_default(), false)),
        ];
        for (ak, key, label, add) in [("/contact/emails", EMAILS, "Email", "Add an email"), ("/contact/phones", PHONES, "Phone", "Add a phone")] {
            for k in self.get(t, key)?.unwrap_or_default().into_keys() {
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
            FormAct::Field(row) => {
                // a field of an absent struct: write the whole struct with its defaults first
                if !row.path.steps().is_empty() && self.db.get(t, self.db.key(&row.ak)?)?.is_none() {
                    self.init_struct(t, &row.ak)?;
                }
                self.set_field(t, row, text)
            }
            FormAct::RenameKey { ak, old } => {
                let key = self.db.key(ak)?;
                let entry: Labeled = self.db.at(t, key.clone()).path(Path::root().push(old.as_str())).get()?.unwrap_or(Labeled { label: String::new(), pref: false });
                if text == old {
                    return Ok(());
                }
                self.db.write_with(|w| {
                    w.at(t, key.clone()).path(Path::root()).remove_key(&old.to_string())?;
                    if !text.is_empty() {
                        w.at(t, key.clone()).path(Path::root()).put(&text.to_string(), &entry)?;
                    }
                    Ok(())
                })
            }
            FormAct::AddKey { ak } => {
                if text.is_empty() {
                    return Ok(());
                }
                let key = self.db.key(ak)?;
                self.db.write_with(|w| w.at(t, key.clone()).path(Path::root()).put(&text.to_string(), &Labeled { label: String::new(), pref: false }))
            }
        }
    }

    fn init_struct(&self, t: Tid, ak: &str) -> Result<()> {
        use crate::contact::{NAMES, Names, ORG, Org};
        match ak {
            "/contact/names" => self.db.write_with(|w| w.at(t, NAMES).set(&Names { given: None, family: None, middle: None, prefix: None, suffix: None })),
            "/contact/org" => self.db.write_with(|w| w.at(t, ORG).set(&Org { name: String::new(), department: String::new(), title: String::new() })),
            _ => Ok(()),
        }
    }
}
