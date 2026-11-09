//! The raw view's content (notes/app.md Raw view): every aspect of a thing, read and edited from
//! its schema-declared type alone. Values are flattened into rows down to scalars (structs by
//! field, maps by key, enum payloads, `option`s as their value or empty); a scalar row is
//! edited as text and written at its path. Lists, sets, counters, texts and untyped values are
//! shown, not edited.

use crate::store::Reader;
use crate::store::Data;
use crate::view::{Act, Action, Block, Cx, Do, Facet, FormRow, Input, Section};
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

impl crate::store::Reader {
    /// The fallback view's rows for `t`, by aspect key.
    pub fn field_rows(&self, t: Tid) -> Result<Vec<Row>> {
        let mut aks: Vec<String> = self.db.aspects(t)?.into_iter().map(|a| a.as_str().to_string()).collect();
        aks.retain(|a| !crate::store::SYSTEM.contains(&a.as_str()));
        aks.sort();
        let mut rows = Vec::new();
        for ak in aks {
            let key = self.db.aspect_key(&ak)?;
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

}

impl Data {
    /// Writes the text of an edited row. An unparsable number or case is `Invalid`.
    pub fn set_field(&self, t: Tid, row: &Row, text: &str) -> Result<()> {
        let key = self.db.aspect_key(&row.ak)?;
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

#[derive(Clone, Debug, PartialEq)]
struct SaveRow(Tid, Row);

impl Action for SaveRow {
    fn run(&self, act: &Act, input: &Input) -> Result<()> {
        let Input::Text(text) = input else { return Ok(()) };
        act.set_field(self.0, &self.1, text)
    }
}

pub struct FieldsFacet;
pub static FACET: FieldsFacet = FieldsFacet;

impl Facet for FieldsFacet {
    fn id(&self) -> &'static str {
        "fields"
    }
    fn claims(&self, _: &str) -> bool {
        false
    }
    fn applies(&self, _: &Reader, _: Tid) -> Result<bool> {
        Ok(true)
    }
    fn universal(&self) -> bool {
        true
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let rows = (**cx).field_rows(t)?;
        let rows = rows
            .into_iter()
            .map(|r| FormRow {
                label: r.label.clone(),
                sub: r.ty.clone(),
                depth: r.depth,
                value: r.value.clone(),
                placeholder: if r.optional { "none".into() } else { String::new() },
                save: (r.edit != Edit::None).then(|| Do::new(SaveRow(t, r))),
            })
            .collect();
        Ok(Section::of(vec![Block::Label("All fields".into()), Block::Line("Every aspect from its schema type. Enter saves a field; an empty optional field becomes none.".into()), Block::Form { rows, wide: true }]))
    }
}
